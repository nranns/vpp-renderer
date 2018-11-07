/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/find_iterator.hpp>
#include <boost/algorithm/string/finder.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/asio/ip/host_name.hpp>
#include <boost/asio/placeholders.hpp>
#include <boost/functional/hash.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/system/error_code.hpp>
#include <sstream>
#include <string>

#include <modelgbp/arp/OpcodeEnumT.hpp>
#include <modelgbp/gbp/AddressResModeEnumT.hpp>
#include <modelgbp/gbp/BcastFloodModeEnumT.hpp>
#include <modelgbp/gbp/ConnTrackEnumT.hpp>
#include <modelgbp/gbp/DirectionEnumT.hpp>
#include <modelgbp/gbp/IntraGroupPolicyEnumT.hpp>
#include <modelgbp/gbp/RoutingModeEnumT.hpp>
#include <modelgbp/gbp/UnknownFloodModeEnumT.hpp>
#include <modelgbp/l2/EtherTypeEnumT.hpp>
#include <modelgbp/l4/TcpFlagsEnumT.hpp>

#include <opflexagent/Endpoint.h>
#include <opflexagent/EndpointManager.h>
#include "VppManager.h"
#include <opflexagent/logging.h>
#include <vom/acl_binding.hpp>
#include <vom/bridge_domain.hpp>
#include <vom/bridge_domain_arp_entry.hpp>
#include <vom/bridge_domain_entry.hpp>
#include <vom/interface.hpp>
#include <vom/sub_interface.hpp>
#include <vom/l2_binding.hpp>
#include <vom/l2_emulation.hpp>
#include <vom/l3_binding.hpp>
#include <vom/nat_binding.hpp>
#include <vom/nat_static.hpp>
#include <vom/neighbour.hpp>
#include <vom/om.hpp>
#include <vom/route.hpp>
#include <vom/route_domain.hpp>
#include <vom/gbp_endpoint.hpp>
#include <vom/gbp_endpoint_group.hpp>
#include <vom/gbp_contract.hpp>
#include <vom/gbp_recirc.hpp>
#include <vom/gbp_subnet.hpp>

using std::string;
using std::shared_ptr;
using std::vector;
using std::unordered_set;
using std::bind;
using boost::optional;
using boost::asio::deadline_timer;
using boost::asio::ip::address;
using boost::asio::ip::address_v6;
using boost::asio::placeholders::error;
using opflex::modb::URI;
using opflex::modb::MAC;
using opflex::modb::class_id_t;
using modelgbp::gbpe::L24Classifier;
using modelgbp::l2::EtherTypeEnumT;

using namespace modelgbp::gbp;
using namespace modelgbp::gbpe;

namespace opflexagent {

typedef EndpointListener::uri_set_t uri_set_t;

static const char* ID_NAMESPACES[] = {
    "floodDomain",     "bridgeDomain", "routingDomain", "contract",
    "externalNetwork", "secGroup",     "secGroupSet"};

static const char* ID_NMSPC_FD = ID_NAMESPACES[0];
static const char* ID_NMSPC_BD = ID_NAMESPACES[1];
static const char* ID_NMSPC_RD = ID_NAMESPACES[2];
static const char* ID_NMSPC_CON = ID_NAMESPACES[3];
static const char* ID_NMSPC_EXTNET = ID_NAMESPACES[4];
static const char* ID_NMSPC_SECGROUP = ID_NAMESPACES[5];
static const char* ID_NMSPC_SECGROUP_SET = ID_NAMESPACES[6];

static string getSecGrpSetId(const uri_set_t& secGrps) {
    std::stringstream ss;
    bool notfirst = false;
    for (const URI& uri : secGrps) {
        if (notfirst)
            ss << ",";
        notfirst = true;
        ss << uri.toString();
    }
    return ss.str();
}

/**
 * An owner of the objects VPP learns during boot-up
 */
static const std::string BOOT_KEY = "__boot__";

VppManager::VppManager(Agent& agent_, IdGenerator& idGen_, VOM::HW::cmd_q* q)
    : agent(agent_),
      idGen(idGen_),
      taskQueue(agent.getAgentIOService()),
      m_uplink(taskQueue),
      stopping(false) {

    VOM::HW::init(q);
    VOM::OM::init();

    agent.getFramework().registerPeerStatusListener(this);
}

void VppManager::start() {

    LOG(INFO) << "start vpp manager";
    for (size_t i = 0; i < sizeof(ID_NAMESPACES) / sizeof(char*); i++) {
        /*
         * start the namespace ID's at a non-zero offset so the default tables
         * are never used.
         */
        idGen.initNamespace(ID_NAMESPACES[i], 100);
    }
    initPlatformConfig();

    /*
     * make sure the first event in the task Q is the blocking
     * connection initiation to VPP ...
     */
    taskQueue.dispatch("init-connection",
                       bind(&VppManager::handleInitConnection, this));

    /**
     * DO BOOT
     */

    /**
     * ... followed by vpp boot dump
     */
    taskQueue.dispatch("boot-dump", bind(&VppManager::handleBoot, this));

    /**
     * ... followed by uplink configuration
     */
    taskQueue.dispatch("uplink-configure",
                       bind(&VppManager::handleUplinkConfigure, this));

    /**
     * ... followed by cross connect configuration
     */
    taskQueue.dispatch("xconnect-configure",
                       bind(&VppManager::handleXConnectConfigure, this));
}

void VppManager::handleCloseConnection() {
    if (!hw_connected)
        return;

    m_cmds.clear();

    VOM::HW::disconnect();

    LOG(DEBUG) << "Close VPP connection";

}

void VppManager::handleInitConnection() {
    if (stopping)
        return;

    LOG(DEBUG) << "Open VPP connection";

    while (VOM::HW::connect() != true)
        ;

    hw_connected = true;
    /**
     * We are insterested in getting interface events from VPP
     */
    shared_ptr<VOM::cmd> itf(new VOM::interface_cmds::events_cmd(*this));

    VOM::HW::enqueue(itf);
    m_cmds.push_back(itf);

    /**
     * Scehdule a timer to Poll for HW livensss
     */
    m_poll_timer.reset(new deadline_timer(agent.getAgentIOService()));
    m_poll_timer->expires_from_now(boost::posix_time::seconds(3));
    m_poll_timer->async_wait(bind(&VppManager::handleHWPollTimer, this, error));
}

void VppManager::handleUplinkConfigure() {
    if (stopping)
        return;

    m_uplink.configure(boost::asio::ip::host_name());
}

void VppManager::handleXConnectConfigure() {
    if (stopping)
        return;

    m_xconnect.configure_xconnect();
}

void VppManager::handleSweepTimer(const boost::system::error_code& ec) {
    if (stopping || ec)
        return;

    LOG(INFO) << "sweep boot data";

    /*
     * the sweep timer was not cancelled, continue with purging old state.
     */
    if (hw_connected)
        VOM::OM::sweep(BOOT_KEY);
    else if (!stopping) {
        m_sweep_timer.reset(new deadline_timer(agent.getAgentIOService()));
        m_sweep_timer->expires_from_now(boost::posix_time::seconds(30));
        m_sweep_timer->async_wait(bind(&VppManager::handleSweepTimer, this,
                                           error));
    }
}

void VppManager::handleHWPollTimer(const boost::system::error_code& ec) {
    if (stopping || ec)
        return;

    if (hw_connected && VOM::HW::poll()) {
        /*
         * re-scehdule a timer to Poll for HW liveness
         */
        m_poll_timer.reset(new deadline_timer(agent.getAgentIOService()));
        m_poll_timer->expires_from_now(boost::posix_time::seconds(3));
        m_poll_timer->async_wait(bind(&VppManager::handleHWPollTimer, this,
                                          error));
        return;
    }

    hw_connected = false;
    VOM::HW::disconnect();
    LOG(DEBUG) << "Reconnecting ....";
    if (VOM::HW::connect()) {
        LOG(DEBUG) << "Replay the state after reconnecting ...";
        VOM::OM::replay();
        hw_connected = true;
    }

    if (!stopping) {
        m_poll_timer.reset(new deadline_timer(agent.getAgentIOService()));
        m_poll_timer->expires_from_now(boost::posix_time::seconds(1));
        m_poll_timer->async_wait(bind(&VppManager::handleHWPollTimer, this,
                                          error));
    } else {
        VOM::HW::disconnect();
    }
}

void VppManager::handleBoot() {
    if (stopping)
        return;

    /**
     * Read the state from VPP
     */
    VOM::OM::populate(BOOT_KEY);
}

void VppManager::registerModbListeners() {
    // Initialize policy listeners
    agent.getEndpointManager().registerListener(this);
    agent.getServiceManager().registerListener(this);
    agent.getExtraConfigManager().registerListener(this);
    agent.getPolicyManager().registerListener(this);
}

void VppManager::stop() {
    stopping = true;

    agent.getEndpointManager().unregisterListener(this);
    agent.getServiceManager().unregisterListener(this);
    agent.getExtraConfigManager().unregisterListener(this);
    agent.getPolicyManager().unregisterListener(this);

    if (m_sweep_timer) {
        m_sweep_timer->cancel();
    }

    if (m_poll_timer) {
        m_poll_timer->cancel();
    }

    taskQueue.dispatch("close-connection",
                       bind(&VppManager::handleCloseConnection, this));

    LOG(DEBUG) << "stop VppManager";
}

void VppManager::setVirtualRouter(bool virtualRouterEnabled, bool routerAdv,
                                  const string& virtualRouterMac) {
    if (virtualRouterEnabled) {
        try {
            uint8_t routerMac[6];
            MAC(virtualRouterMac).toUIntArray(routerMac);
            m_vr = std::make_shared<VPP::VirtualRouter>(
                VPP::VirtualRouter(routerMac));
        } catch (std::invalid_argument) {
            LOG(ERROR) << "Invalid virtual router MAC: " << virtualRouterMac;
        }
    }
}

void VppManager::endpointUpdated(const std::string& uuid) {
    if (stopping)
        return;

    taskQueue.dispatch(uuid,
                       bind(&VppManager::handleEndpointUpdate, this, uuid));
}

void VppManager::serviceUpdated(const std::string& uuid) {
    if (stopping)
        return;

    LOG(INFO) << "Service Update Not supported ";
}

void VppManager::rdConfigUpdated(const opflex::modb::URI& rdURI) {
    domainUpdated(RoutingDomain::CLASS_ID, rdURI);
}

void VppManager::egDomainUpdated(const opflex::modb::URI& egURI) {
    if (stopping)
        return;

    taskQueue.dispatch(
        egURI.toString(),
        bind(&VppManager::handleEndpointGroupDomainUpdate, this, egURI));
}

void VppManager::domainUpdated(class_id_t cid, const URI& domURI) {
    if (stopping)
        return;

    taskQueue.dispatch(domURI.toString(), bind(&VppManager::handleDomainUpdate,
                                               this, cid, domURI));
}

void VppManager::secGroupSetUpdated(
    const EndpointListener::uri_set_t& secGrps) {
    if (stopping)
        return;
    taskQueue.dispatch(
        "setSecGrp:",
        std::bind(&VppManager::handleSecGrpSetUpdate, this, secGrps));
}

void VppManager::secGroupUpdated(const opflex::modb::URI& uri) {
    if (stopping)
        return;
    taskQueue.dispatch("secGrp:",
                       std::bind(&VppManager::handleSecGrpUpdate, this, uri));
}

void VppManager::contractUpdated(const opflex::modb::URI& contractURI) {
    if (stopping)
        return;
    taskQueue.dispatch(
        contractURI.toString(),
        bind(&VppManager::handleContractUpdate, this, contractURI));
}

void VppManager::handle_interface_event(VOM::interface_cmds::events_cmd* e) {
    if (stopping)
        return;
    taskQueue.dispatch("InterfaceEvent",
                       bind(&VppManager::handleInterfaceEvent, this, e));
}

void VppManager::handle_interface_stat(
    VOM::interface_cmds::stats_enable_cmd* e) {
    if (stopping)
        return;
    taskQueue.dispatch("InterfaceStat",
                       bind(&VppManager::handleInterfaceStat, this, e));
}

void VppManager::configUpdated(const opflex::modb::URI& configURI) {
    if (stopping)
        return;
    agent.getAgentIOService().dispatch(
        bind(&VppManager::handleConfigUpdate, this, configURI));
}

void VppManager::portStatusUpdate(const string& portName, uint32_t portNo,
                                  bool fromDesc) {
    if (stopping)
        return;
    agent.getAgentIOService().dispatch(
        bind(&VppManager::handlePortStatusUpdate, this, portName, portNo));
}

void VppManager::peerStatusUpdated(const std::string&, int,
                                   PeerStatus peerStatus) {
    if (stopping)
        return;
}

bool VppManager::getGroupForwardingInfo(const URI& epgURI, uint32_t& vnid,
                                        optional<URI>& rdURI,
                                        uint32_t& rdId,
                                        optional<URI>& bdURI,
                                        uint32_t& bdId) {
    PolicyManager& polMgr = agent.getPolicyManager();
    optional<uint32_t> epgVnid = polMgr.getVnidForGroup(epgURI);
    if (!epgVnid) {
        return false;
    }
    vnid = epgVnid.get();

    optional<shared_ptr<RoutingDomain>> epgRd = polMgr.getRDForGroup(epgURI);
    optional<shared_ptr<BridgeDomain>> epgBd = polMgr.getBDForGroup(epgURI);
    if (!epgBd) {
        return false;
    }

    bdId = rdId = 0;
    if (epgRd) {
        rdURI = epgRd.get()->getURI();
        if (rdURI)
            rdId = getId(RoutingDomain::CLASS_ID, rdURI.get());
    }
    if (epgBd) {
        bdURI = epgBd.get()->getURI();
        bdId = getId(BridgeDomain::CLASS_ID, bdURI.get());
    }
    return true;
}

static string getEpBridgeInterface(const Endpoint& endPoint) {
    const optional<string>& epAccessItf = endPoint.getAccessInterface();
    const optional<string>& epItf = endPoint.getInterfaceName();

    /*
     * the goal here is to get the name of the interface to which the VM
     * is attached.
     */
    if (epAccessItf)
        return epAccessItf.get();
    else if (epItf)
        return epItf.get();
    else
        return {};
}

static VOM::interface::type_t getIntfTypeFromName(string name) {
    if ((name.find("vhost") != string::npos) ||
        (name.find("vhu") != string::npos))
        return VOM::interface::type_t::VHOST;
    else if (name.find("tap") != string::npos)
        return VOM::interface::type_t::TAP;

    return VOM::interface::type_t::AFPACKET;
}

static std::vector<address>
getEpIPs(const opflexagent::Endpoint& endPoint)
{
    /* check and parse the IP-addresses */
    boost::system::error_code ec;
    std::vector<address> ipAddresses;

    const boost::optional<opflex::modb::MAC> mac = endPoint.getMAC();

    for (const std::string& ipStr : endPoint.getIPs()) {
        address addr =
            address::from_string(ipStr, ec);
        if (ec) {
            LOG(opflexagent::WARNING) << "Invalid endpoint IP: " << ipStr << ": "
                                      << ec.message();
        } else {
            ipAddresses.push_back(addr);
        }
    }

    if (mac) {
        address_v6 linkLocalIp(opflexagent::network::construct_link_local_ip_addr(mac.get()));
        if (endPoint.getIPs().find(linkLocalIp.to_string()) ==
            endPoint.getIPs().end())
            ipAddresses.push_back(linkLocalIp);
    }

    return ipAddresses;
}

void VppManager::handleEndpointUpdate(const string& uuid) {
    /*
     * This is an update to all the state related to this endpoint.
     * At the end of processing we want all the state related to this endpint,
     * that we don't touch here, gone.
     */
    VOM::OM::mark_n_sweep ms(uuid);
    boost::system::error_code ec;

    if (stopping)
        return;

    EndpointManager& epMgr = agent.getEndpointManager();
    shared_ptr<const Endpoint> epWrapper = epMgr.getEndpoint(uuid);

    if (!epWrapper) {
        LOG(DEBUG) << "Deleting endpoint " << uuid;
        return;
    }
    LOG(DEBUG) << "Updating endpoint " << uuid;

    optional<URI> epgURI = epMgr.getComputedEPG(uuid);
    if (!epgURI) { // can't do much without EPG
        return;
    }

    const Endpoint& endPoint = *epWrapper.get();
    const uri_set_t& secGrps = endPoint.getSecurityGroups();
    const std::string secGrpId = getSecGrpSetId(secGrps);
    boost::hash<std::string> string_hash;
    const std::string secGrpKey = std::to_string(string_hash(secGrpId));

    int rv;

    uint32_t epgVnid, rdId, bdId;
    optional<URI> bdURI, rdURI;
    if (!getGroupForwardingInfo(epgURI.get(), epgVnid,
                                rdURI, rdId,
                                bdURI, bdId)) {
        return;
    }

    /*
     * the route-domain the endpoint is in.
     */
    route_domain rd(rdId);
    OM::write(uuid, rd);
    bridge_domain bd(bdId, VOM::bridge_domain::learning_mode_t::OFF);
    OM::write(uuid, bd);

    /*
     * VOM GBP Endpoint Group
     */
    shared_ptr<VOM::interface> encap_link =
      m_uplink.mk_interface(epgURI.get().toString(), epgVnid);
    gbp_endpoint_group gepg(epgVnid, *encap_link, rd, bd);
    OM::write(uuid, gepg);

    /*
     * We want a veth interface - admin up
     */
    const string epItfName = getEpBridgeInterface(endPoint);

    if (0 == epItfName.length())
        return;
    std::shared_ptr<VOM::interface> itf;
    uint16_t vlan_id_t;
    if (endPoint.getAccessIfaceVlan()) {
      VOM::interface intf(epItfName, getIntfTypeFromName(epItfName),
                           VOM::interface::admin_state_t::UP, uuid);
      VOM::OM::write(uuid, intf);

      vlan_id_t = endPoint.getAccessIfaceVlan().get();
      VOM::sub_interface sub_itf(intf, interface::admin_state_t::UP, rd, vlan_id_t);
      VOM::OM::write(uuid, sub_itf);
      itf = sub_itf.singular();
    } else {
      VOM::interface intf(epItfName, getIntfTypeFromName(epItfName),
                         VOM::interface::admin_state_t::UP, rd, uuid);
      VOM::OM::write(uuid, intf);
      itf = intf.singular();
    }

    /*
     * If the interface is not created then we cannot do anymore
     */
    if (handle_t::INVALID == itf->handle())
        return;

    /**
     * We are interested in getting detailed interface stats from VPP
     */
    itf->enable_stats(*this, interface::stats_type_t::DETAILED);

    /*
     * Apply Security Groups
     */
    VOM::ACL::l3_list::rules_t in_rules, out_rules;
    VOM::ACL::acl_ethertype::ethertype_rules_t ethertype_rules;

    optional<Endpoint::DHCPv4Config> v4c = endPoint.getDHCPv4Config();
    if (v4c) {
        VOM::ACL::ethertype_rule_t et(ethertype_t::IPV4, direction_t::INPUT);
        ethertype_rules.insert(et);
        VOM::ACL::ethertype_rule_t out_et(ethertype_t::IPV4, direction_t::OUTPUT);
        ethertype_rules.insert(out_et);
        allowDhcpRequest(in_rules, out_rules, EtherTypeEnumT::CONST_IPV4);
    }
    optional<Endpoint::DHCPv6Config> v6c = endPoint.getDHCPv6Config();
    if (v6c) {
        VOM::ACL::ethertype_rule_t et(ethertype_t::IPV6, direction_t::INPUT);
        ethertype_rules.insert(et);
        VOM::ACL::ethertype_rule_t out_et(ethertype_t::IPV6, direction_t::OUTPUT);
        ethertype_rules.insert(out_et);
        allowDhcpRequest(in_rules, out_rules, EtherTypeEnumT::CONST_IPV6);
    }

    buildSecGrpSetUpdate(secGrps, secGrpId, in_rules, out_rules,
                         ethertype_rules);

    if (!ethertype_rules.empty()) {
        VOM::ACL::acl_ethertype a_e(*itf, ethertype_rules);
        VOM::OM::write(uuid, a_e);
    }
    if (!in_rules.empty()) {
        VOM::ACL::l3_list in_acl(secGrpKey + "-in", in_rules);
        VOM::OM::write(uuid, in_acl);

        VOM::ACL::l3_binding in_binding(direction_t::INPUT, *itf, in_acl);
        VOM::OM::write(uuid, in_binding);
    }
    if (!out_rules.empty()) {
        VOM::ACL::l3_list out_acl(secGrpKey + "-out", out_rules);
        VOM::OM::write(uuid, out_acl);

        VOM::ACL::l3_binding out_binding(direction_t::OUTPUT, *itf, out_acl);
        VOM::OM::write(uuid, out_binding);
    }

    uint8_t macAddr[6] = {0};
    bool hasMac = endPoint.getMAC() != boost::none;

    if (hasMac)
        endPoint.getMAC().get().toUIntArray(macAddr);

    /* check and parse the IP-addresses */
    vector<address> ipAddresses = getEpIPs(endPoint);

    VOM::ACL::l2_list::rules_t rules;
    if (itf->handle().value()) {
        if (endPoint.isPromiscuousMode()) {
            VOM::ACL::l2_rule rulev6(50, VOM::ACL::action_t::PERMIT,
                                     VOM::route::prefix_t::ZEROv6, macAddr,
                                     VOM::mac_address_t::ZERO);

            VOM::ACL::l2_rule rulev4(51, VOM::ACL::action_t::PERMIT,
                                     VOM::route::prefix_t::ZERO, macAddr,
                                     VOM::mac_address_t::ZERO);
            rules.insert(rulev4);
            rules.insert(rulev6);
        } else if (hasMac) {
            VOM::ACL::l2_rule rulev6(20, VOM::ACL::action_t::PERMIT,
                                     VOM::route::prefix_t::ZEROv6, macAddr,
                                     VOM::mac_address_t::ONE);

            VOM::ACL::l2_rule rulev4(21, VOM::ACL::action_t::PERMIT,
                                     VOM::route::prefix_t::ZERO, macAddr,
                                     VOM::mac_address_t::ONE);
            rules.insert(rulev4);
            rules.insert(rulev6);

            for (const address& ipAddr : ipAddresses) {
                // Allow IPv4/IPv6 packets from port with EP IP address
                VOM::route::prefix_t pfx(ipAddr, ipAddr.is_v4() ? 32 : 128);
                if (ipAddr.is_v6()) {
                    VOM::ACL::l2_rule rule(30, VOM::ACL::action_t::PERMIT, pfx,
                                           macAddr, VOM::mac_address_t::ONE);
                    rules.insert(rule);
                } else {
                    VOM::ACL::l2_rule rule(31, VOM::ACL::action_t::PERMIT, pfx,
                                           macAddr, VOM::mac_address_t::ONE);
                    rules.insert(rule);
                }
            }
        }

        for (const Endpoint::virt_ip_t& vip : endPoint.getVirtualIPs()) {
            network::cidr_t vip_cidr;
            if (!network::cidr_from_string(vip.second, vip_cidr)) {
                LOG(WARNING) << "Invalid endpoint VIP (CIDR): " << vip.second;
                continue;
            }
            uint8_t vmac[6];
            vip.first.toUIntArray(vmac);

            for (const address& ipAddr : ipAddresses) {
                if (!network::cidr_contains(vip_cidr, ipAddr)) {
                    continue;
                }
                VOM::route::prefix_t pfx(ipAddr, ipAddr.is_v4() ? 32 : 128);
                if (ipAddr.is_v6()) {
                    VOM::ACL::l2_rule rule(60, VOM::ACL::action_t::PERMIT, pfx,
                                           vmac, VOM::mac_address_t::ONE);
                    rules.insert(rule);
                } else {
                    VOM::ACL::l2_rule rule(61, VOM::ACL::action_t::PERMIT, pfx,
                                           vmac, VOM::mac_address_t::ONE);
                    rules.insert(rule);
                }
            }
        }

        VOM::ACL::l2_list acl(uuid, rules);
        VOM::OM::write(uuid, acl);

        VOM::ACL::l2_binding binding(VOM::direction_t::INPUT, *itf, acl);
        VOM::OM::write(uuid, binding);
    }

    /*
     * EP's interface is in the EPG's BD
     */
    VOM::l2_binding l2itf(*itf, bd);
    if (endPoint.getAccessIfaceVlan()) {
        l2itf.set(l2_binding::l2_vtr_op_t::L2_VTR_POP_1, vlan_id_t);
    }

    VOM::OM::write(uuid, l2itf);

    /*
     * Create/get the BVI interface for the EPG
     */
    VOM::interface bvi("bvi-" + std::to_string(bd.id()),
                       VOM::interface::type_t::BVI,
                       VOM::interface::admin_state_t::UP, rd);
    VOM::OM::write(uuid, bvi);

    if (hasMac) {
        mac_address_t vmac(macAddr);
        /*
         * An entry in the BD's L2 FIB to forward traffic to the end-point
         */
        VOM::bridge_domain_entry be(bd, vmac, *itf);
        VOM::OM::write(uuid, be);

        /*
         * add a GDBP endpoint
         */
        VOM::gbp_endpoint gbpe(*itf, ipAddresses, vmac, gepg);
        VOM::OM::write(uuid, gbpe);

        /*
         * Floating IP addresses -> NAT
         */
        if (m_vr &&
            (RoutingModeEnumT::CONST_ENABLED ==
             agent.getPolicyManager().getEffectiveRoutingMode(epgURI.get()))) {
          auto ipms = endPoint.getIPAddressMappings();

          if (0 != ipms.size())
            {
              /*
               * there are floating IPs, we need a recirulation interface
               * for this EP's EPG. These are NAT outside and input feautre
               * since packets are sent to these interface in order to have
               * the out2in translation applied.
               */
                VOM::interface recirc_itf("recirc-" + std::to_string(epgVnid),
                                          interface::type_t::LOOPBACK,
                                          VOM::interface::admin_state_t::UP,
                                          rd);
              OM::write(uuid, recirc_itf);

              l2_binding recirc_l2b(recirc_itf, bd);
              OM::write(uuid, recirc_l2b);

              nat_binding recirc_nb4(recirc_itf,
                                     direction_t::INPUT,
                                     l3_proto_t::IPV4,
                                     nat_binding::zone_t::OUTSIDE);
              OM::write(uuid, recirc_nb4);

              nat_binding recirc_nb6(recirc_itf,
                                     direction_t::INPUT,
                                     l3_proto_t::IPV6,
                                     nat_binding::zone_t::OUTSIDE);
              OM::write(uuid, recirc_nb6);

              gbp_recirc grecirc(recirc_itf,
                                 gbp_recirc::type_t::INTERNAL,
                                 gepg);
              OM::write(uuid, grecirc);

              for(const Endpoint::IPAddressMapping& ipm : ipms) {
                if (!ipm.getMappedIP() || !ipm.getEgURI())
                  continue;

                address mappedIp =
                  address::from_string(ipm.getMappedIP().get(), ec);
                if (ec) continue;

                address floatingIp;
                if (ipm.getFloatingIP()) {
                  floatingIp =
                    address::from_string(ipm.getFloatingIP().get(), ec);
                  if (ec) continue;
                  if (floatingIp.is_v4() != mappedIp.is_v4()) continue;
                }

                uint32_t fepgVnid, frdId, fbdId;
                optional<URI> fbdURI, frdURI;
                if (!getGroupForwardingInfo(ipm.getEgURI().get(),
                                            fepgVnid,
                                            frdURI, frdId,
                                            fbdURI, fbdId))
                  continue;

                LOG(DEBUG) << "EP:" << uuid << " - add Floating IP"
                           << floatingIp << " => "
                           << mappedIp;

                /*
                 * Route and Bridge Domains and the external EPG
                 */
                route_domain ext_rd(frdId);
                OM::write(uuid, ext_rd);
                bridge_domain ext_bd(fbdId, VOM::bridge_domain::learning_mode_t::OFF);
                OM::write(uuid, ext_bd);
                VOM::interface ext_bvi("bvi-" + std::to_string(fbdId),
                                       VOM::interface::type_t::BVI,
                                       VOM::interface::admin_state_t::UP, ext_rd);
                VOM::OM::write(uuid, ext_bvi);

                /*
                 * Route for the floating IP via the internal EPG's recirc
                 */
                VOM::route::prefix_t fp_pfx(floatingIp);
                VOM::route::ip_route fp_route(ext_rd, fp_pfx,
                                              {recirc_itf,
                                               fp_pfx.l3_proto().to_nh_proto(),
                                               route::path::flags_t::DVR});
                VOM::OM::write(uuid, fp_route);

                VOM::neighbour fp_ne(ext_bvi, floatingIp, {macAddr});
                VOM::OM::write(uuid, fp_ne);

                /*
                 * reply to ARP's for the floating IP
                 */
                VOM::bridge_domain_arp_entry fp_bae(ext_bd, floatingIp, {macAddr});
                VOM::OM::write(uuid, fp_bae);

                /*
                 * Bridge L2 packets addressed to the VM to the recirc
                 * interface
                 */
                VOM::bridge_domain_entry fp_be(ext_bd, macAddr, recirc_itf);
                VOM::OM::write(uuid, fp_be);

                /*
                 * NAT static mapping
                 */
                VOM::nat_static ns(rd, mappedIp, floatingIp);
                VOM::OM::write(uuid, ns);
              }
            }
        }
    }

    /*
     * That's all folks ... destructor of mark_n_sweep calls the
     * sweep for the stale state
     */
}

void VppManager::handleEndpointGroupDomainUpdate(const URI& epgURI) {
    const string& epg_uuid = epgURI.toString();

    /*
     * Mark all of this EPG's state stale. this RAII pattern
     * will sweep all state that is not updated.
     */
    VOM::OM::mark_n_sweep ms(epg_uuid);

    if (stopping)
        return;

    PolicyManager& pm = agent.getPolicyManager();

    if (!agent.getPolicyManager().groupExists(epgURI)) {
        LOG(DEBUG) << "Deleting endpoint-group:" << epgURI;
        return;
    }

    uint32_t epgVnid, rdId, bdId;
    optional<URI> bdURI, rdURI;
    if (!getGroupForwardingInfo(epgURI, epgVnid,
                                rdURI, rdId,
                                bdURI, bdId)) {
        LOG(DEBUG) << "NOT Updating endpoint-group:" << epgURI;
        return;
    }
    LOG(DEBUG) << "Updating endpoint-group:" << epgURI;

    /*
     * Construct the Bridge and routing Domains
     */
    VOM::bridge_domain bd(bdId, VOM::bridge_domain::learning_mode_t::OFF);
    VOM::OM::write(epg_uuid, bd);
    VOM::route_domain rd(rdId);
    VOM::OM::write(epg_uuid, rd);

    /*
     * Construct the encap-link
     */
    shared_ptr<VOM::interface> encap_link =
        m_uplink.mk_interface(epg_uuid, epgVnid);

    /*
     * GBP Endpoint Group
     */
    gbp_endpoint_group gepg(epgVnid, *encap_link, rd, bd);
    OM::write(epg_uuid, gepg);

    /*
     * Add the encap-link to the BD
     *
     * If the encap link is a VLAN, then set the pop VTR operation on the
     * link so that the VLAN tag is correctly pop/pushed on rx/tx resp.
     */
    VOM::l2_binding l2_upl(*encap_link, bd);
    if (VOM::interface::type_t::VXLAN != encap_link->type()) {
        l2_upl.set(l2_binding::l2_vtr_op_t::L2_VTR_POP_1, epgVnid);
    }
    VOM::OM::write(epg_uuid, l2_upl);

    /*
     * Create a BVI interface for the EPG and add it to the bridge-domain
     */
    VOM::interface bvi("bvi-" + std::to_string(bd.id()),
                       VOM::interface::type_t::BVI,
                       VOM::interface::admin_state_t::UP, rd);
    if (m_vr) {
        /*
         * Set the BVI's MAC address to the Virtual Router
         * address, so packets destined to the VR are handled
         * by layer 3.
         */
        bvi.set(m_vr->mac());
    }
    VOM::OM::write(epg_uuid, bvi);

    /*
     * The BVI is the NAT inside interface for the VMs
     */
    nat_binding nb6(bvi,
                    direction_t::INPUT,
                    l3_proto_t::IPV6,
                    nat_binding::zone_t::INSIDE);
    nat_binding nb4(bvi,
                    direction_t::INPUT,
                    l3_proto_t::IPV4,
                    nat_binding::zone_t::INSIDE);
    OM::write(epg_uuid, nb4);
    OM::write(epg_uuid, nb6);

    /*
     * Add the BVIs to the BD
     */
    VOM::l2_binding l2_bvi(bvi, bd);
    VOM::OM::write(epg_uuid, l2_bvi);

    /*
     * the bridge is not in learning mode. So add an L2FIB entry for the BVI
     */
    VOM::bridge_domain_entry be(bd, bvi.l2_address().to_mac(), bvi);
    VOM::OM::write(epg_uuid, be);

    /*
     * For each subnet the EPG has
     */
    PolicyManager::subnet_vector_t subnets;
    agent.getPolicyManager().getSubnetsForGroup(epgURI, subnets);

    for (shared_ptr<Subnet>& sn : subnets) {
        optional<address> routerIp = PolicyManager::getRouterIpForSubnet(*sn);

        if (!sn->getPrefixLen() || !sn->getAddress())
            continue;

        if (routerIp) {
            boost::asio::ip::address raddr = routerIp.get();
            /*
             * - apply the host prefix on the BVI
             * - add an entry into the ARP Table for it.
             */
            VOM::l3_binding l3(bvi, {raddr});
            VOM::OM::write(epg_uuid, l3);

            VOM::bridge_domain_arp_entry bae(bd, raddr,
                                             bvi.l2_address().to_mac());
            VOM::OM::write(epg_uuid, bae);
        }
        /*
         * The subnet is an internal 'GBP subnet' i.e. it is one where
         * the egress the is the EPG's uplink. And the EPG is chosen
         * based on the packet's source port
         */
        route::prefix_t pfx(sn->getAddress().get(),
                            sn->getPrefixLen().get());
        gbp_subnet gs(rd, pfx.low(), gbp_subnet::type_t::STITCHED_INTERNAL);
        OM::write(epg_uuid, gs);
    }
}

network::subnets_t VppManager::getRDSubnets(const URI& rdURI) {
    /*
     * this is a cut-n-paste from IntflowManager.
     */
    network::subnets_t intSubnets;

    optional<shared_ptr<RoutingDomain>> rd =
        RoutingDomain::resolve(agent.getFramework(), rdURI);

    if (!rd) {
        return intSubnets;
    }

    vector<shared_ptr<RoutingDomainToIntSubnetsRSrc>> subnets_list;
    rd.get()->resolveGbpRoutingDomainToIntSubnetsRSrc(subnets_list);
    for (auto& subnets_ref : subnets_list) {
        optional<URI> subnets_uri = subnets_ref->getTargetURI();
        PolicyManager::resolveSubnets(agent.getFramework(), subnets_uri,
                                      intSubnets);
    }
    shared_ptr<const RDConfig> rdConfig =
        agent.getExtraConfigManager().getRDConfig(rdURI);
    if (rdConfig) {
        for (const std::string& cidrSn : rdConfig->getInternalSubnets()) {
            network::cidr_t cidr;
            if (network::cidr_from_string(cidrSn, cidr)) {
                intSubnets.insert(
                    make_pair(cidr.first.to_string(), cidr.second));
            } else {
                LOG(ERROR) << "Invalid CIDR subnet: " << cidrSn;
            }
        }
    }

    return intSubnets;
}

void VppManager::handleRoutingDomainUpdate(const URI& rdURI) {
    OM::mark_n_sweep ms(rdURI.toString());

    optional<shared_ptr<RoutingDomain>> op_opf_rd =
        RoutingDomain::resolve(agent.getFramework(), rdURI);

    if (!op_opf_rd) {
        LOG(DEBUG) << "Cleaning up for RD: " << rdURI;
        idGen.erase(getIdNamespace(RoutingDomain::CLASS_ID), rdURI.toString());
        return;
    }
    shared_ptr<RoutingDomain> opf_rd = op_opf_rd.get();

    const string& rd_uuid = rdURI.toString();

    LOG(DEBUG) << "Importing routing domain:" << rdURI;

    /*
     * get all the subnets that are internal to this route domain
     */
    network::subnets_t intSubnets = getRDSubnets(rdURI);
    boost::system::error_code ec;

    /*
     * create (or at least own) VPP's route-domain object
     */
    uint32_t rdId = getId(RoutingDomain::CLASS_ID, rdURI);

    VOM::route_domain rd(rdId);
    VOM::OM::write(rd_uuid, rd);

    /*
     * For each internal Subnet
     */
    for (const network::subnet_t& sn : intSubnets) {
        /*
         * still a little more song and dance before we can get
         * our hands on an address ...
         */
        address addr = address::from_string(sn.first, ec);
        if (ec)
            continue;

        LOG(DEBUG) << "Importing routing domain:" << rdURI
                   << " subnet:" << addr
                   << "/" << std::to_string(sn.second);

        /*
         * add a route for the subnet in VPP's route-domain via
         * the EPG's uplink, DVR styleee
         */
        gbp_subnet gs(rd, {addr, sn.second},
                      gbp_subnet::type_t::STITCHED_INTERNAL);
        OM::write(rd_uuid, gs);
    }

    /*
     * for each external subnet
     */
    vector<shared_ptr<L3ExternalDomain>> extDoms;
    opf_rd.get()->resolveGbpL3ExternalDomain(extDoms);
    for (shared_ptr<L3ExternalDomain>& extDom : extDoms) {
        vector<shared_ptr<L3ExternalNetwork>> extNets;
        extDom->resolveGbpL3ExternalNetwork(extNets);

        for (shared_ptr<L3ExternalNetwork> net : extNets) {
            vector<shared_ptr<ExternalSubnet>> extSubs;
            net->resolveGbpExternalSubnet(extSubs);
            optional<shared_ptr<L3ExternalNetworkToNatEPGroupRSrc>> natRef =
                net->resolveGbpL3ExternalNetworkToNatEPGroupRSrc();
            optional<uint32_t> natEpgVnid = boost::none;
            optional<URI> natEpg = boost::none;

            if (natRef) {
                natEpg = natRef.get()->getTargetURI();
                if (natEpg)
                    natEpgVnid =
                        agent.getPolicyManager().getVnidForGroup(natEpg.get());
            }

            for (auto extSub : extSubs) {
                if (!extSub->isAddressSet() || !extSub->isPrefixLenSet())
                    continue;

                LOG(DEBUG) << "Importing routing domain:" << rdURI
                           << " external:" << extDom->getName("n/a")
                           << " external-net:" << net->getName("n/a")
                           << " external-sub:" << extSub->getAddress("n/a")
                           << "/" << std::to_string(extSub->getPrefixLen(99))
                           << " nat-epg:" << natEpg
                           << " nat-epg-id:" << natEpgVnid;

                address addr =
                    address::from_string(extSub->getAddress().get(), ec);
                if (ec)
                    continue;

                if (natEpgVnid) {
                    /*
                     * there's a NAT EPG for this subnet. create its RD, BD
                     * and EPG.
                     */
                    uint32_t nat_epgVnid, nat_rdId, nat_bdId;
                    optional<URI> nat_bdURI, nat_rdURI;
                    if (!getGroupForwardingInfo(natEpg.get(), nat_epgVnid,
                                                nat_rdURI, nat_rdId,
                                                nat_bdURI,  nat_bdId)) {
                        return;
                    }
                    VOM::route_domain nat_rd(nat_rdId);
                    VOM::OM::write(rd_uuid, nat_rd);
                    VOM::bridge_domain nat_bd(nat_bdId);
                    VOM::OM::write(rd_uuid, nat_bd);

                    shared_ptr<VOM::interface> encap_link =
                        m_uplink.mk_interface(rd_uuid, natEpgVnid.get());

                    gbp_endpoint_group nat_epg(natEpgVnid.get(),
                                               *encap_link,
                                               nat_rd, nat_bd);
                    OM::write(rd_uuid, nat_epg);

                    /*
                     * The external-subnet is a route via the NAT-EPG's recirc.
                     * the recirc is a NAT outside interface to get NAT applied in-2out
                     */

                    /* setup the recirc interface */
                    VOM::interface nat_recirc_itf("recirc-" + std::to_string(natEpgVnid.get()),
                                                  interface::type_t::LOOPBACK,
                                                  VOM::interface::admin_state_t::UP,
                                                  nat_rd);
                    OM::write(rd_uuid, nat_recirc_itf);

                    l2_binding nat_recirc_l2b(nat_recirc_itf, nat_bd);
                    OM::write(rd_uuid, nat_recirc_l2b);

                    nat_binding nat_recirc_nb4(nat_recirc_itf,
                                               direction_t::INPUT,
                                               l3_proto_t::IPV4,
                                               nat_binding::zone_t::OUTSIDE);
                    OM::write(rd_uuid, nat_recirc_nb4);

                    nat_binding nat_recirc_nb6(nat_recirc_itf,
                                               direction_t::INPUT,
                                               l3_proto_t::IPV6,
                                               nat_binding::zone_t::OUTSIDE);
                    OM::write(rd_uuid, nat_recirc_nb6);

                    gbp_recirc nat_grecirc(nat_recirc_itf,
                                           gbp_recirc::type_t::EXTERNAL,
                                           nat_epg);
                    OM::write(rd_uuid, nat_grecirc);

                    /* add the route for the ext-subnet */
                    gbp_subnet gs(rd,
                                  {addr, extSub->getPrefixLen().get()},
                                  nat_grecirc, nat_epg);
                    OM::write(rd_uuid, gs);
                } else {
                    /*
                     * through this EPG's uplink port
                     */
                    gbp_subnet gs(rd, {addr, extSub->getPrefixLen().get()},
                                  gbp_subnet::type_t::STITCHED_INTERNAL);
                    OM::write(rd_uuid, gs);
                }
            }
        }
    }
}

void VppManager::handleDomainUpdate(class_id_t cid, const URI& domURI) {
    if (stopping)
        return;

    LOG(DEBUG) << "Updating domain " << domURI;

    switch (cid) {
    case RoutingDomain::CLASS_ID:
        handleRoutingDomainUpdate(domURI);
        break;
    case Subnet::CLASS_ID:
        if (!Subnet::resolve(agent.getFramework(), domURI)) {
            LOG(DEBUG) << "Cleaning up for Subnet: " << domURI;
        }
        break;
    case BridgeDomain::CLASS_ID:
        if (!BridgeDomain::resolve(agent.getFramework(), domURI)) {
            LOG(DEBUG) << "Cleaning up for BD: " << domURI;
            idGen.erase(getIdNamespace(cid), domURI.toString());
        }
        break;
    case FloodDomain::CLASS_ID:
        if (!FloodDomain::resolve(agent.getFramework(), domURI)) {
            LOG(DEBUG) << "Cleaning up for FD: " << domURI;
            idGen.erase(getIdNamespace(cid), domURI.toString());
        }
        break;
    case FloodContext::CLASS_ID:
        if (!FloodContext::resolve(agent.getFramework(), domURI)) {
            LOG(DEBUG) << "Cleaning up for FloodContext: " << domURI;
        }
        break;
    case L3ExternalNetwork::CLASS_ID:
        if (!L3ExternalNetwork::resolve(agent.getFramework(), domURI)) {
            LOG(DEBUG) << "Cleaning up for L3ExtNet: " << domURI;
            idGen.erase(getIdNamespace(cid), domURI.toString());
        }
        break;
    }
}

void VppManager::handleInterfaceEvent(VOM::interface_cmds::events_cmd* e) {
    LOG(DEBUG) << "Interface Event: " << *e;
    if (stopping)
        return;

    std::lock_guard<VOM::interface_cmds::events_cmd> lg(*e);

    for (auto& msg : *e) {
        auto& payload = msg.get_payload();

        VOM::handle_t handle(payload.sw_if_index);
        shared_ptr<VOM::interface> sp = VOM::interface::find(handle);

        if (sp) {
            VOM::interface::oper_state_t oper_state =
                VOM::interface::oper_state_t::from_int(payload.link_up_down);

            LOG(DEBUG) << "Interface Event: " << sp->to_string()
                       << " state: " << oper_state.to_string();

            sp->set(oper_state);
        }
    }

    e->flush();
}

void VppManager::handleInterfaceStat(VOM::interface_cmds::stats_enable_cmd* e) {
    LOG(DEBUG) << "Interface Stat: " << *e;
    if (stopping)
        return;

    EndpointManager& epMgr = agent.getEndpointManager();
    std::lock_guard<VOM::interface_cmds::stats_enable_cmd> lg(*e);

    for (auto& msg : *e) {
        auto& payload = msg.get_payload();

        for (int i = 0; i < payload.count; i++) {
            EndpointManager::EpCounters counters;
            std::unordered_set<std::string> endpoints;
            auto& data = payload.data[i];

            VOM::handle_t handle(data.sw_if_index);
            shared_ptr<VOM::interface> sp = VOM::interface::find(handle);
            if (!sp)
                return;

            LOG(DEBUG) << "Interface Stat: " << sp->to_string()
                      << " stat rx_packets: " << data.rx_packets
                      << " stat rx_bytes: " << data.rx_bytes
                      << " stat rx_unicast_packets: " << data.rx_unicast_packets
                      << " stat rx_multicast_packets: " << data.rx_multicast_packets
                      << " stat rx_broadcast_packets: " << data.rx_broadcast_packets
                      << " stat tx_packets: " << data.tx_packets
                      << " stat tx_bytes: " << data.tx_bytes
                      << " stat tx_unicast_packets: " << data.tx_unicast_packets
                      << " stat tx_multicast_packets: " << data.tx_multicast_packets
                      << " stat tx_broadcast_packets: " << data.tx_broadcast_packets;

            epMgr.getEndpointsByAccessIface(sp->name(), endpoints);

            memset(&counters, 0, sizeof(counters));
            counters.txPackets = data.tx_packets;
            counters.rxPackets = data.rx_packets;
            counters.txBytes = data.tx_bytes;
            counters.rxBytes = data.rx_bytes;
            counters.rxUnicast = data.rx_unicast_packets;
            counters.txUnicast = data.tx_unicast_packets;
            counters.rxBroadcast = data.rx_broadcast_packets;
            counters.txBroadcast = data.tx_broadcast_packets;
            counters.rxMulticast = data.rx_multicast_packets;
            counters.txMulticast = data.tx_multicast_packets;
            // counters.txDrop = data.tx_dropped;
            // counters.rxDrop = data.rx_dropped;

            for (const std::string& uuid : endpoints) {
                if (counters.rxDrop == std::numeric_limits<uint64_t>::max())
                    counters.rxDrop = 0;
                if (counters.txDrop == std::numeric_limits<uint64_t>::max())
                    counters.txDrop = 0;
                if (counters.txPackets == std::numeric_limits<uint64_t>::max())
                    counters.txPackets = 0;
                if (counters.rxPackets == std::numeric_limits<uint64_t>::max())
                    counters.rxPackets = 0;
                if (counters.txBroadcast == std::numeric_limits<uint64_t>::max())
                    counters.txBroadcast = 0;
                if (counters.rxBroadcast == std::numeric_limits<uint64_t>::max())
                    counters.rxBroadcast = 0;
                if (counters.txMulticast == std::numeric_limits<uint64_t>::max())
                    counters.txMulticast = 0;
                if (counters.rxMulticast == std::numeric_limits<uint64_t>::max())
                    counters.rxMulticast = 0;
                if (counters.txUnicast == std::numeric_limits<uint64_t>::max())
                    counters.txUnicast = 0;
                if (counters.rxUnicast == std::numeric_limits<uint64_t>::max())
                    counters.rxUnicast = 0;
                if (counters.rxBytes == std::numeric_limits<uint64_t>::max())
                    counters.rxBytes = 0;
                if (counters.txBytes == std::numeric_limits<uint64_t>::max())
                    counters.txBytes = 0;
                epMgr.updateEndpointCounters(uuid, counters);
            }
        }
    }

    e->flush();
}

void VppManager::getGroupVnid(const unordered_set<URI>& uris,
                              unordered_set<uint32_t>& ids) {
    PolicyManager& pm = agent.getPolicyManager();
    for (const URI& u : uris) {
        optional<uint32_t> vnid = pm.getVnidForGroup(u);
        optional<shared_ptr<RoutingDomain> > rd;
        if (vnid) {
            rd = pm.getRDForGroup(u);
        } else {
            rd = pm.getRDForL3ExtNet(u);
            if (rd) {
                vnid = getExtNetVnid(u);
            }
        }
        if (vnid && rd) {
            ids.insert(vnid.get());
        }
    }
}
uint32_t VppManager::getExtNetVnid(const opflex::modb::URI& uri) {
    // External networks are assigned private VNIDs that have bit 31 (MSB)
    // set to 1. This is fine because legal VNIDs are 24-bits or less.
    return (getId(L3ExternalNetwork::CLASS_ID, uri) | (1 << 31));
}

std::shared_ptr<gbp_endpoint_group>
VppManager::getEndPointGroup (const std::string& uuid,
                              const URI &epgURI)
{
    uint32_t epgVnid, rdId, bdId;
    optional<URI> bdURI, rdURI;
    if (!getGroupForwardingInfo(epgURI, epgVnid,
                                rdURI, rdId,
                                bdURI, bdId)) {
        return {};
    }

    route_domain rd(rdId);
    OM::write(uuid, rd);
    bridge_domain bd(bdId, VOM::bridge_domain::learning_mode_t::OFF);
    OM::write(uuid, bd);

    /*
     * VOM GBP Endpoint Group
     */
    shared_ptr<VOM::interface> encap_link =
        m_uplink.mk_interface(uuid, epgVnid);
    gbp_endpoint_group gepg(epgVnid, *encap_link, rd, bd);
    OM::write(uuid, gepg);

    return gepg.singular();
}

void VppManager::handleContractUpdate(const opflex::modb::URI& contractURI) {
    LOG(DEBUG) << "Updating contract " << contractURI;
    if (stopping)
        return;

    const string& uuid = contractURI.toString();

    VOM::OM::mark_n_sweep ms(uuid);

    PolicyManager& polMgr = agent.getPolicyManager();
    if (!polMgr.contractExists(contractURI)) {
        // Contract removed
        return;
    }

    PolicyManager::uri_set_t provURIs;
    PolicyManager::uri_set_t consURIs;
    PolicyManager::uri_set_t intraURIs;
    polMgr.getContractProviders(contractURI, provURIs);
    polMgr.getContractConsumers(contractURI, consURIs);
    polMgr.getContractIntra(contractURI, intraURIs);

    typedef unordered_set<uint32_t> id_set_t;
    id_set_t provIds;
    id_set_t consIds;
    id_set_t intraIds;
    getGroupVnid(provURIs, provIds);
    getGroupVnid(consURIs, consIds);

    PolicyManager::rule_list_t rules;
    polMgr.getContractRules(contractURI, rules);

    for (const uint32_t& pvnid : provIds) {
        for (const uint32_t& cvnid : consIds) {
            if (pvnid == cvnid)
                /* intra group is allowed by default */
                continue;

            LOG(DEBUG) << "Contract prov:" << pvnid
                       << " cons:" << cvnid;

            /*
             * At this point we are implementing only the neutron virtual
             * router concept. So we use a permit any-any rule and rely
             * only on the GDBP EPG restructions
             */
            VOM::ACL::l3_rule rule(0,
                                   VOM::ACL::action_t::PERMIT,
                                   route::prefix_t::ZERO,
                                   route::prefix_t::ZERO);

            VOM::ACL::l3_list acl(uuid, {rule});
            VOM::OM::write(uuid, acl);

            VOM::gbp_contract gbpc(pvnid, cvnid, acl);
            VOM::OM::write(uuid, gbpc);
        }
    }
}

void VppManager::initPlatformConfig() {

    using namespace modelgbp::platform;

    optional<shared_ptr<Config>> config = Config::resolve(
        agent.getFramework(), agent.getPolicyManager().getOpflexDomain());
}

void VppManager::handleConfigUpdate(const opflex::modb::URI& configURI) {
    LOG(DEBUG) << "Updating platform config " << configURI;
    if (stopping)
        return;

    initPlatformConfig();

    /**
     * Now that we are known to be opflex connected,
     * Scehdule a timer to sweep the state we read when we first connected
     * to VPP.
     */
    m_sweep_timer.reset(new deadline_timer(agent.getAgentIOService()));
    m_sweep_timer->expires_from_now(boost::posix_time::seconds(30));
    m_sweep_timer->async_wait(bind(&VppManager::handleSweepTimer, this, error));
}

void VppManager::handlePortStatusUpdate(const string& portName, uint32_t) {
    LOG(DEBUG) << "Port-status update for " << portName;
    if (stopping)
        return;
}

typedef std::function<bool(opflex::ofcore::OFFramework&, const string&,
                           const string&)>
    IdCb;

static const IdCb ID_NAMESPACE_CB[] = {
    IdGenerator::uriIdGarbageCb<FloodDomain>,
    IdGenerator::uriIdGarbageCb<BridgeDomain>,
    IdGenerator::uriIdGarbageCb<RoutingDomain>,
    IdGenerator::uriIdGarbageCb<Contract>,
    IdGenerator::uriIdGarbageCb<L3ExternalNetwork>};

const char* VppManager::getIdNamespace(class_id_t cid) {
    const char* nmspc = NULL;
    switch (cid) {
    case RoutingDomain::CLASS_ID:
        nmspc = ID_NMSPC_RD;
        break;
    case BridgeDomain::CLASS_ID:
        nmspc = ID_NMSPC_BD;
        break;
    case FloodDomain::CLASS_ID:
        nmspc = ID_NMSPC_FD;
        break;
    case Contract::CLASS_ID:
        nmspc = ID_NMSPC_CON;
        break;
    case L3ExternalNetwork::CLASS_ID:
        nmspc = ID_NMSPC_EXTNET;
        break;
    default:
        assert(false);
    }
    return nmspc;
}

uint32_t VppManager::getId(class_id_t cid, const URI& uri) {
    return idGen.getId(getIdNamespace(cid), uri.toString());
}

VPP::Uplink& VppManager::uplink() { return m_uplink; }
VPP::CrossConnect& VppManager::crossConnect() { return m_xconnect; }

void VppManager::handleSecGrpUpdate(const opflex::modb::URI& uri) {
    if (stopping)
        return;
    unordered_set<uri_set_t> secGrpSets;
    agent.getEndpointManager().getSecGrpSetsForSecGrp(uri, secGrpSets);
    for (const uri_set_t& secGrpSet : secGrpSets)
        secGroupSetUpdated(secGrpSet);
}

void VppManager::allowDhcpRequest(VOM::ACL::l3_list::rules_t& in_rules,
                                  VOM::ACL::l3_list::rules_t& out_rules,
                                  uint16_t etherType) {

    VOM::ACL::action_t act = VOM::ACL::action_t::PERMIT;

    if (etherType == EtherTypeEnumT::CONST_IPV4) {
        route::prefix_t pfx = route::prefix_t::ZERO;

        VOM::ACL::l3_rule rule(200, act, pfx, pfx);

        rule.set_proto(17);
        rule.set_src_from_port(68);
        rule.set_src_to_port(68);
        rule.set_dst_from_port(67);
        rule.set_dst_to_port(67);

        in_rules.insert(rule);

        VOM::ACL::l3_rule out_rule(200, act, pfx, pfx);

        out_rule.set_proto(17);
        out_rule.set_src_from_port(67);
        out_rule.set_src_to_port(67);
        out_rule.set_dst_from_port(68);
        out_rule.set_dst_to_port(68);

        out_rules.insert(out_rule);
    } else {
        route::prefix_t pfx = route::prefix_t::ZEROv6;

        VOM::ACL::l3_rule rule(200, act, pfx, pfx);

        rule.set_proto(17);
        rule.set_src_from_port(546);
        rule.set_src_to_port(546);
        rule.set_dst_from_port(547);
        rule.set_dst_to_port(547);

        in_rules.insert(rule);

        VOM::ACL::l3_rule out_rule(200, act, pfx, pfx);

        out_rule.set_proto(17);
        out_rule.set_src_from_port(547);
        out_rule.set_src_to_port(547);
        out_rule.set_dst_from_port(546);
        out_rule.set_dst_to_port(546);

        out_rules.insert(out_rule);
    }
}

void setParamUpdate(L24Classifier& cls, VOM::ACL::l3_rule& rule) {

    using modelgbp::l4::TcpFlagsEnumT;

    if (cls.isArpOpcSet()) {
        rule.set_proto(cls.getArpOpc().get());
    }

    if (cls.isProtSet()) {
        rule.set_proto(cls.getProt(0));
    }

    if (cls.isSFromPortSet()) {
        rule.set_src_from_port(cls.getSFromPort(0));
    }

    if (cls.isSToPortSet()) {
        rule.set_src_to_port(cls.getSToPort(0));
    }

    if (cls.isDFromPortSet()) {
        rule.set_dst_from_port(cls.getDFromPort(0));
    }

    if (cls.isDToPortSet()) {
        rule.set_dst_to_port(cls.getDToPort(0));
    }

    if (6 == cls.getProt(0) && cls.isTcpFlagsSet()) {
        rule.set_tcp_flags_mask(
            cls.getTcpFlags(TcpFlagsEnumT::CONST_UNSPECIFIED));
        rule.set_tcp_flags_value(
            cls.getTcpFlags(TcpFlagsEnumT::CONST_UNSPECIFIED));
    }

    if (6 == cls.getProt(0) || 17 == cls.getProt(0)) {
        if (rule.srcport_or_icmptype_last() == 0)
            rule.set_src_to_port(65535);
        if (rule.dstport_or_icmpcode_last() == 0)
            rule.set_dst_to_port(65535);
    }

    if (1 == cls.getProt(0) || 58 == cls.getProt(0)) {
        if (rule.srcport_or_icmptype_last() == 0)
            rule.set_src_to_port(255);
        if (rule.dstport_or_icmpcode_last() == 0)
            rule.set_dst_to_port(255);
    }
}

void VppManager::buildSecGrpSetUpdate(const uri_set_t& secGrps,
                                      const std::string& secGrpId,
                                      VOM::ACL::l3_list::rules_t& in_rules,
                                      VOM::ACL::l3_list::rules_t& out_rules,
                                      VOM::ACL::acl_ethertype::ethertype_rules_t&
                                      ethertype_rules) {
    if (secGrps.empty()) {
       // VOM::OM::remove(secGrpId);
        return;
    }

    LOG(DEBUG) << "building security group update";

    for (const opflex::modb::URI& secGrp : secGrps) {
        PolicyManager::rule_list_t rules;
        agent.getPolicyManager().getSecGroupRules(secGrp, rules);

        for (shared_ptr<PolicyRule>& pc : rules) {
            uint8_t dir = pc->getDirection();
            const shared_ptr<L24Classifier>& cls = pc->getL24Classifier();
            uint32_t priority = pc->getPriority();
            const ethertype_t& etherType =
                ethertype_t::from_numeric_val(cls->getEtherT(
                EtherTypeEnumT::CONST_UNSPECIFIED));
            VOM::ACL::action_t act = VOM::ACL::action_t::from_bool(
                pc->getAllow(),
                cls->getConnectionTracking(ConnTrackEnumT::CONST_NORMAL));

            if (dir == DirectionEnumT::CONST_BIDIRECTIONAL ||
                        dir == DirectionEnumT::CONST_IN) {
                VOM::ACL::ethertype_rule_t et(etherType, direction_t::OUTPUT);
                ethertype_rules.insert(et);
            }
            if (dir == DirectionEnumT::CONST_BIDIRECTIONAL ||
                        dir == DirectionEnumT::CONST_OUT) {
                VOM::ACL::ethertype_rule_t et(etherType, direction_t::INPUT);
                ethertype_rules.insert(et);
            }

            if (etherType != EtherTypeEnumT::CONST_IPV4 && etherType !=
                EtherTypeEnumT::CONST_IPV6) {
                LOG(WARNING) << "Security Group Rule for Protocol " <<
                    etherType.to_string() << " ,(IPv4/IPv6) Security" <<
                    "Rules are allowed";
                continue;
            }

            if (!pc->getRemoteSubnets().empty()) {
                boost::optional<const network::subnets_t&> remoteSubs;
                remoteSubs = pc->getRemoteSubnets();
                for (const network::subnet_t& sub : remoteSubs.get()) {
                    bool is_v6 =
                        boost::asio::ip::address::from_string(sub.first)
                            .is_v6();

                    if ((etherType == EtherTypeEnumT::CONST_IPV4 && is_v6) ||
                        (etherType == EtherTypeEnumT::CONST_IPV6 && !is_v6))
                        continue;

                    route::prefix_t ip(sub.first, sub.second);
                    route::prefix_t ip2(route::prefix_t::ZERO);

                    if (etherType == EtherTypeEnumT::CONST_IPV6) {
                        ip2 = route::prefix_t::ZEROv6;
                    }

                    if (dir == DirectionEnumT::CONST_BIDIRECTIONAL ||
                        dir == DirectionEnumT::CONST_IN) {
                        VOM::ACL::l3_rule rule(priority, act, ip, ip2);
                        setParamUpdate(*cls, rule);
                        out_rules.insert(rule);
                    }
                    if (dir == DirectionEnumT::CONST_BIDIRECTIONAL ||
                        dir == DirectionEnumT::CONST_OUT) {
                        VOM::ACL::l3_rule rule(priority, act, ip2, ip);
                        setParamUpdate(*cls, rule);
                        in_rules.insert(rule);
                    }
                }
            } else {
                route::prefix_t srcIp(route::prefix_t::ZERO);
                route::prefix_t dstIp(route::prefix_t::ZERO);

                if (etherType == EtherTypeEnumT::CONST_IPV6) {
                    srcIp = route::prefix_t::ZEROv6;
                    dstIp = route::prefix_t::ZEROv6;
                }

                VOM::ACL::l3_rule rule(priority, act, srcIp, dstIp);
                setParamUpdate(*cls, rule);
                if (dir == DirectionEnumT::CONST_BIDIRECTIONAL ||
                    dir == DirectionEnumT::CONST_IN) {
                    out_rules.insert(rule);
                }
                if (dir == DirectionEnumT::CONST_BIDIRECTIONAL ||
                    dir == DirectionEnumT::CONST_OUT) {
                    in_rules.insert(rule);
                }
            }
        }
    }
}

void VppManager::handleSecGrpSetUpdate(const uri_set_t& secGrps) {
/*    LOG(DEBUG) << "Updating security group set";
    if (stopping)
        return;

    VOM::ACL::l3_list::rules_t in_rules, out_rules;
    VOM::ACL::acl_ethertype::ethertype_rules_t ethertype_rules;
    const std::string secGrpId = getSecGrpSetId(secGrps);
    shared_ptr<VOM::ACL::l3_list> in_acl, out_acl;

    buildSecGrpSetUpdate(secGrps, secGrpId, in_rules, out_rules,
                         ethertype_rules);

    if (in_rules.empty() && out_rules.empty() && ethertype_rules.empty()) {
        LOG(WARNING) << "in and out rules are empty";
        return;
    }

    EndpointManager& epMgr = agent.getEndpointManager();
    std::unordered_set<std::string> eps;
    epMgr.getEndpointsForSecGrps(secGrps, eps);

    for (const std::string& uuid : eps) {

        VOM::OM::mark_n_sweep ms(uuid);

        const Endpoint& endPoint = *epMgr.getEndpoint(uuid).get();
        const string vppInterfaceName = getEpBridgeInterface(endPoint);

        if (0 == vppInterfaceName.length())
            continue;

        shared_ptr<VOM::interface> itf =
            VOM::interface::find(vppInterfaceName);

        if (!itf)
            continue;

        if (!ethertype_rules.empty()) {
            VOM::ACL::acl_ethertype a_e(*itf, ethertype_rules);
            VOM::OM::write(uuid, a_e);
        }
        if (!in_rules.empty()) {
            VOM::ACL::l3_list inAcl(secGrpId + "in", in_rules);
            VOM::OM::write(uuid, inAcl);

            VOM::ACL::l3_binding in_binding(direction_t::INPUT, *itf, inAcl);
            VOM::OM::write(uuid, in_binding);
        }
        if (!out_rules.empty()) {
            VOM::ACL::l3_list outAcl(secGrpId + "out", out_rules);
            VOM::OM::write(uuid, outAcl);
            VOM::ACL::l3_binding out_binding(direction_t::OUTPUT, *itf,
                                             outAcl);
            VOM::OM::write(uuid, out_binding);
        }
    }
*/
}

}; // namespace opflexagent

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */
