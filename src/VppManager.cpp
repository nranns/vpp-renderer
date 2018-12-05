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
#include <memory>
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

#include "VppEndPointGroupManager.hpp"
#include "VppEndPointManager.hpp"
#include "VppIdGen.hpp"
#include "VppLog.hpp"
#include "VppManager.h"
#include "VppSecurityGroupManager.hpp"
#include "VppUtil.hpp"

#include <opflexagent/Endpoint.h>
#include <opflexagent/EndpointManager.h>

#include <vom/bridge_domain.hpp>
#include <vom/gbp_contract.hpp>
#include <vom/gbp_endpoint.hpp>
#include <vom/gbp_endpoint_group.hpp>
#include <vom/gbp_recirc.hpp>
#include <vom/gbp_subnet.hpp>
#include <vom/interface.hpp>
#include <vom/l2_binding.hpp>
#include <vom/l3_binding.hpp>
#include <vom/nat_binding.hpp>
#include <vom/om.hpp>
#include <vom/route.hpp>
#include <vom/route_domain.hpp>
#include <vom/sub_interface.hpp>

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
using namespace VPP;

namespace VPP
{

typedef opflexagent::EndpointListener::uri_set_t uri_set_t;

/**
 * An owner of the objects VPP learns during boot-up
 */
static const std::string BOOT_KEY = "__boot__";

VppManager::VppManager(opflexagent::Agent &agent_,
                       opflexagent::IdGenerator &idGen_, VOM::HW::cmd_q *q)
    : agent(agent_)
    , m_id_gen(idGen_)
    , m_task_queue(agent.getAgentIOService())
    , m_uplink(m_task_queue)
    , stopping(false)
{
    VOM::HW::init(q);
    VOM::OM::init();

    agent.getFramework().registerPeerStatusListener(this);
}

void VppManager::start()
{
    VLOGI << "start vpp manager: mode: " << agent.getRendererForwardingMode();

    /*
     * create the update delegators
     */
    m_epm = std::make_shared<EndPointManager>(agent, m_id_gen, m_uplink, m_vr);
    m_epgm =
        std::make_shared<EndPointGroupManager>(agent, m_id_gen, m_uplink, m_vr);

    initPlatformConfig();

    /*
     * make sure the first event in the task Q is the blocking
     * connection initiation to VPP ...
     */
    m_task_queue.dispatch("init-connection",
                          bind(&VppManager::handleInitConnection, this));

    /**
     * DO BOOT
     */

    /**
     * ... followed by vpp boot dump
     */
    m_task_queue.dispatch("boot-dump", bind(&VppManager::handleBoot, this));

    /**
     * ... followed by uplink configuration
     */
    m_task_queue.dispatch("uplink-configure",
                          bind(&VppManager::handleUplinkConfigure, this));

    /**
     * ... followed by cross connect configuration
     */
    m_task_queue.dispatch("xconnect-configure",
                          bind(&VppManager::handleXConnectConfigure, this));
}

void VppManager::handleCloseConnection()
{
    if (!hw_connected) return;

    m_cmds.clear();

    VOM::HW::disconnect();

    OLOGD << "Close VPP connection";
}

void VppManager::handleInitConnection()
{
    if (stopping) return;

    OLOGD << "Open VPP connection";

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

void VppManager::handleUplinkConfigure()
{
    if (stopping) return;

    m_uplink.configure(boost::asio::ip::host_name());
}

void VppManager::handleXConnectConfigure()
{
    if (stopping) return;

    m_xconnect.configure_xconnect();
}

void VppManager::handleSweepTimer(const boost::system::error_code &ec)
{
    if (stopping || ec) return;

    VLOGI << "sweep boot data";

    /*
     * the sweep timer was not cancelled, continue with purging old state.
     */
    if (hw_connected)
        VOM::OM::sweep(BOOT_KEY);
    else if (!stopping)
    {
        m_sweep_timer.reset(new deadline_timer(agent.getAgentIOService()));
        m_sweep_timer->expires_from_now(boost::posix_time::seconds(30));
        m_sweep_timer->async_wait(
            bind(&VppManager::handleSweepTimer, this, error));
    }
}

void VppManager::handleHWPollTimer(const boost::system::error_code &ec)
{
    if (stopping || ec) return;

    if (hw_connected && VOM::HW::poll())
    {
        /*
         * re-scehdule a timer to Poll for HW liveness
         */
        m_poll_timer.reset(new deadline_timer(agent.getAgentIOService()));
        m_poll_timer->expires_from_now(boost::posix_time::seconds(3));
        m_poll_timer->async_wait(
            bind(&VppManager::handleHWPollTimer, this, error));
        return;
    }

    hw_connected = false;
    VOM::HW::disconnect();
    OLOGD << "Reconnecting ....";
    if (VOM::HW::connect())
    {
        OLOGD << "Replay the state after reconnecting ...";
        VOM::OM::replay();
        hw_connected = true;
    }

    if (!stopping)
    {
        m_poll_timer.reset(new deadline_timer(agent.getAgentIOService()));
        m_poll_timer->expires_from_now(boost::posix_time::seconds(1));
        m_poll_timer->async_wait(
            bind(&VppManager::handleHWPollTimer, this, error));
    }
    else
    {
        VOM::HW::disconnect();
    }
}

void VppManager::handleBoot()
{
    if (stopping) return;

    /**
     * Read the state from VPP
     */
    VOM::OM::populate(BOOT_KEY);
}

void VppManager::registerModbListeners()
{
    // Initialize policy listeners
    agent.getEndpointManager().registerListener(this);
    agent.getServiceManager().registerListener(this);
    agent.getExtraConfigManager().registerListener(this);
    agent.getPolicyManager().registerListener(this);
}

void VppManager::stop()
{
    stopping = true;

    agent.getEndpointManager().unregisterListener(this);
    agent.getServiceManager().unregisterListener(this);
    agent.getExtraConfigManager().unregisterListener(this);
    agent.getPolicyManager().unregisterListener(this);

    if (m_sweep_timer)
    {
        m_sweep_timer->cancel();
    }

    if (m_poll_timer)
    {
        m_poll_timer->cancel();
    }

    m_task_queue.dispatch("close-connection",
                          bind(&VppManager::handleCloseConnection, this));

    OLOGD << "stop VppManager";
}

void VppManager::setVirtualRouter(bool virtualRouterEnabled, bool routerAdv,
                                  const string &virtualRouterMac)
{
    if (virtualRouterEnabled)
    {
        try
        {
            uint8_t routerMac[6];
            MAC(virtualRouterMac).toUIntArray(routerMac);
            m_vr = std::make_shared<VirtualRouter>(VirtualRouter(routerMac));
        }
        catch (std::invalid_argument)
        {
            VLOGE << "Invalid virtual router MAC: " << virtualRouterMac;
        }
    }
}

void VppManager::endpointUpdated(const std::string &uuid)
{
    if (stopping) return;

    m_task_queue.dispatch(uuid,
                          bind(&EndPointManager::handle_update, *m_epm, uuid));
}

void VppManager::serviceUpdated(const std::string &uuid)
{
    if (stopping) return;

    VLOGI << "Service Update Not supported ";
}

void VppManager::rdConfigUpdated(const opflex::modb::URI &rdURI)
{
    domainUpdated(RoutingDomain::CLASS_ID, rdURI);
}

void VppManager::egDomainUpdated(const opflex::modb::URI &egURI)
{
    if (stopping) return;

    m_task_queue.dispatch(
        egURI.toString(),
        bind(&EndPointGroupManager::handle_update, *m_epgm, egURI));
}

void VppManager::domainUpdated(class_id_t cid, const URI &domURI)
{
    if (stopping) return;

    m_task_queue.dispatch(
        domURI.toString(),
        bind(&VppManager::handleDomainUpdate, this, cid, domURI));
}

void VppManager::secGroupSetUpdated(const EndpointListener::uri_set_t &secGrps)
{
    if (stopping) return;
    m_task_queue.dispatch(
        "setSecGrp:",
        std::bind(&VppManager::handleSecGrpSetUpdate, this, secGrps));
}

void VppManager::secGroupUpdated(const opflex::modb::URI &uri)
{
    if (stopping) return;
    m_task_queue.dispatch(
        "secGrp:", std::bind(&VppManager::handleSecGrpUpdate, this, uri));
}

void VppManager::contractUpdated(const opflex::modb::URI &contractURI)
{
    if (stopping) return;
    m_task_queue.dispatch(
        contractURI.toString(),
        bind(&VppManager::handleContractUpdate, this, contractURI));
}

void VppManager::handle_interface_event(VOM::interface_cmds::events_cmd *e)
{
    if (stopping) return;
    m_task_queue.dispatch("InterfaceEvent",
                          bind(&VppManager::handleInterfaceEvent, this, e));
}

void VppManager::configUpdated(const opflex::modb::URI &configURI)
{
    VLOGI << "Config Updated ";
    if (stopping) return;
    agent.getAgentIOService().dispatch(
        bind(&VppManager::handleConfigUpdate, this, configURI));
}

void VppManager::portStatusUpdate(const string &portName, uint32_t portNo,
                                  bool fromDesc)
{
    if (stopping) return;
    agent.getAgentIOService().dispatch(
        bind(&VppManager::handlePortStatusUpdate, this, portName, portNo));
}

void VppManager::peerStatusUpdated(const std::string &, int,
                                   PeerStatus peerStatus)
{
    if (stopping) return;
}

void VppManager::handle_uplink_ready()
{
    VLOGI << "Uplink Ready ";
    switch (agent.getRendererForwardingMode())
    {
    case opflex::ofcore::OFConstants::STITCHED_MODE:
        break;
    case opflex::ofcore::OFConstants::TRANSPORT_MODE:
    {
        boost::asio::ip::address_v4 v4, v6, mac;

        agent.getV4Proxy(v4);
        agent.getV4Proxy(v6);
        agent.getV4Proxy(mac);

        m_spine_proxy = std::make_shared<SpineProxy>(
            m_uplink.local_address().to_v4(), v4, v6, mac);
        break;
    }
    }
}

opflexagent::network::subnets_t VppManager::getRDSubnets(const URI &rdURI)
{
    /*
     * this is a cut-n-paste from IntflowManager.
     */
    opflexagent::network::subnets_t intSubnets;

    /* boost::optional<std::shared_ptr<RoutingDomain>> rd = */
    /*     RoutingDomain::resolve(agent.getFramework(), rdURI); */

    /* if (!rd) */
    /* { */
    /*     return intSubnets; */
    /* } */

    /* vector<shared_ptr<RoutingDomainToIntSubnetsRSrc>> subnets_list; */
    /* rd.get()->resolveGbpRoutingDomainToIntSubnetsRSrc(subnets_list); */
    /* for (auto &subnets_ref : subnets_list) */
    /* { */
    /*     optional<URI> subnets_uri = subnets_ref->getTargetURI(); */
    /*     PolicyManager::resolveSubnets(agent.getFramework(), subnets_uri, */
    /*                                   intSubnets); */
    /* } */
    /* shared_ptr<const RDConfig> rdConfig = */
    /*     agent.getExtraConfigManager().getRDConfig(rdURI); */
    /* if (rdConfig) */
    /* { */
    /*     for (const std::string &cidrSn : rdConfig->getInternalSubnets()) */
    /*     { */
    /*         network::cidr_t cidr; */
    /*         if (network::cidr_from_string(cidrSn, cidr)) */
    /*         { */
    /*             intSubnets.insert( */
    /*                 make_pair(cidr.first.to_string(), cidr.second)); */
    /*         } */
    /*         else */
    /*         { */
    /*             VLOGE << "Invalid CIDR subnet: " << cidrSn; */
    /*         } */
    /*     } */
    /* } */

    return intSubnets;
}

void VppManager::handleRoutingDomainUpdate(const URI &rdURI)
{
    /* OM::mark_n_sweep ms(rdURI.toString()); */

    /* optional<shared_ptr<RoutingDomain>> op_opf_rd = */
    /*     RoutingDomain::resolve(agent.getFramework(), rdURI); */

    /* if (!op_opf_rd) */
    /* { */
    /*     OLOGD << "Cleaning up for RD: " << rdURI; */
    /*     m_id_gen.erase(RoutingDomain::CLASS_ID, rdURI); */
    /*     return; */
    /* } */
    /* shared_ptr<RoutingDomain> opf_rd = op_opf_rd.get(); */

    /* const string &rd_uuid = rdURI.toString(); */

    /* OLOGD << "Importing routing domain:" << rdURI; */

    /* /\* */
    /*  * get all the subnets that are internal to this route domain */
    /*  *\/ */
    /* network::subnets_t intSubnets = getRDSubnets(rdURI); */
    /* boost::system::error_code ec; */

    /* /\* */
    /*  * create (or at least own) VPP's route-domain object */
    /*  *\/ */
    /* uint32_t rdId = m_id_gen.get(RoutingDomain::CLASS_ID, rdURI); */

    /* VOM::route_domain rd(rdId); */
    /* VOM::OM::write(rd_uuid, rd); */

    /* /\* */
    /*  * For each internal Subnet */
    /*  *\/ */
    /* for (const network::subnet_t &sn : intSubnets) */
    /* { */
    /*     /\* */
    /*      * still a little more song and dance before we can get */
    /*      * our hands on an address ... */
    /*      *\/ */
    /*     address addr = address::from_string(sn.first, ec); */
    /*     if (ec) continue; */

    /*     OLOGD << "Importing routing domain:" << rdURI << " subnet:" << addr
     */
    /*                << "/" << std::to_string(sn.second); */

    /*     /\* */
    /*      * add a route for the subnet in VPP's route-domain via */
    /*      * the EPG's uplink, DVR styleee */
    /*      *\/ */
    /*     gbp_subnet gs(rd, {addr, sn.second}, */
    /*                   gbp_subnet::type_t::STITCHED_INTERNAL); */
    /*     OM::write(rd_uuid, gs); */
    /* } */

    /* /\* */
    /*  * for each external subnet */
    /*  *\/ */
    /* vector<shared_ptr<L3ExternalDomain>> extDoms; */
    /* opf_rd.get()->resolveGbpL3ExternalDomain(extDoms); */
    /* for (shared_ptr<L3ExternalDomain> &extDom : extDoms) */
    /* { */
    /*     vector<shared_ptr<L3ExternalNetwork>> extNets; */
    /*     extDom->resolveGbpL3ExternalNetwork(extNets); */

    /*     for (shared_ptr<L3ExternalNetwork> net : extNets) */
    /*     { */
    /*         vector<shared_ptr<ExternalSubnet>> extSubs; */
    /*         net->resolveGbpExternalSubnet(extSubs); */
    /*         optional<shared_ptr<L3ExternalNetworkToNatEPGroupRSrc>> natRef =
     */
    /*             net->resolveGbpL3ExternalNetworkToNatEPGroupRSrc(); */
    /*         optional<uint32_t> natEpgVnid = boost::none; */
    /*         optional<URI> natEpg = boost::none; */

    /*         if (natRef) */
    /*         { */
    /*             natEpg = natRef.get()->getTargetURI(); */
    /*             if (natEpg) */
    /*                 natEpgVnid = */
    /*                     agent.getPolicyManager().getVnidForGroup(natEpg.get());
     */
    /*         } */

    /*         for (auto extSub : extSubs) */
    /*         { */
    /*             if (!extSub->isAddressSet() || !extSub->isPrefixLenSet()) */
    /*                 continue; */

    /*             OLOGD << "Importing routing domain:" << rdURI */
    /*                        << " external:" << extDom->getName("n/a") */
    /*                        << " external-net:" << net->getName("n/a") */
    /*                        << " external-sub:" << extSub->getAddress("n/a")
     */
    /*                        << "/" << std::to_string(extSub->getPrefixLen(99))
     */
    /*                        << " nat-epg:" << natEpg */
    /*                        << " nat-epg-id:" << natEpgVnid; */

    /*             address addr = */
    /*                 address::from_string(extSub->getAddress().get(), ec); */
    /*             if (ec) continue; */

    /*             if (natEpgVnid) */
    /*             { */
    /*                 /\* */
    /*                  * there's a NAT EPG for this subnet. create its RD, BD
     */
    /*                  * and EPG. */
    /*                  *\/ */
    /*                 uint32_t nat_epgVnid, nat_rdId, nat_bdId; */
    /*                 optional<URI> nat_bdURI, nat_rdURI; */
    /*                 if (!getGroupForwardingInfo(natEpg.get(), nat_epgVnid, */
    /*                                             nat_rdURI, nat_rdId,
     * nat_bdURI, */
    /*                                             nat_bdId)) */
    /*                 { */
    /*                     return; */
    /*                 } */
    /*                 VOM::route_domain nat_rd(nat_rdId); */
    /*                 VOM::OM::write(rd_uuid, nat_rd); */
    /*                 VOM::bridge_domain nat_bd(nat_bdId); */
    /*                 VOM::OM::write(rd_uuid, nat_bd); */

    /*                 shared_ptr<VOM::interface> encap_link = */
    /*                     m_uplink.mk_interface(rd_uuid, natEpgVnid.get()); */

    /*                 gbp_endpoint_group nat_epg(natEpgVnid.get(), *encap_link,
     */
    /*                                            nat_rd, nat_bd); */
    /*                 OM::write(rd_uuid, nat_epg); */

    /*                 /\* */
    /*                  * The external-subnet is a route via the NAT-EPG's
     * recirc. */
    /*                  * the recirc is a NAT outside interface to get NAT
     * applied */
    /*                  * in-2out */
    /*                  *\/ */

    /*                 /\* setup the recirc interface *\/ */
    /*                 VOM::interface nat_recirc_itf( */
    /*                     "recirc-" + std::to_string(natEpgVnid.get()), */
    /*                     interface::type_t::LOOPBACK, */
    /*                     VOM::interface::admin_state_t::UP, nat_rd); */
    /*                 OM::write(rd_uuid, nat_recirc_itf); */

    /*                 l2_binding nat_recirc_l2b(nat_recirc_itf, nat_bd); */
    /*                 OM::write(rd_uuid, nat_recirc_l2b); */

    /*                 nat_binding nat_recirc_nb4( */
    /*                     nat_recirc_itf, direction_t::INPUT, l3_proto_t::IPV4,
     */
    /*                     nat_binding::zone_t::OUTSIDE); */
    /*                 OM::write(rd_uuid, nat_recirc_nb4); */

    /*                 nat_binding nat_recirc_nb6( */
    /*                     nat_recirc_itf, direction_t::INPUT, l3_proto_t::IPV6,
     */
    /*                     nat_binding::zone_t::OUTSIDE); */
    /*                 OM::write(rd_uuid, nat_recirc_nb6); */

    /*                 gbp_recirc nat_grecirc( */
    /*                     nat_recirc_itf, gbp_recirc::type_t::EXTERNAL,
     * nat_epg); */
    /*                 OM::write(rd_uuid, nat_grecirc); */

    /*                 /\* add the route for the ext-subnet *\/ */
    /*                 gbp_subnet gs(rd, {addr, extSub->getPrefixLen().get()},
     */
    /*                               nat_grecirc, nat_epg); */
    /*                 OM::write(rd_uuid, gs); */
    /*             } */
    /*             else */
    /*             { */
    /*                 /\* */
    /*                  * through this EPG's uplink port */
    /*                  *\/ */
    /*                 gbp_subnet gs(rd, {addr, extSub->getPrefixLen().get()},
     */
    /*                               gbp_subnet::type_t::STITCHED_INTERNAL); */
    /*                 OM::write(rd_uuid, gs); */
    /*             } */
    /*         } */
    /*     } */
    /* } */
}

void VppManager::handleDomainUpdate(class_id_t cid, const URI &domURI)
{
    if (stopping) return;

    OLOGD << "Updating domain " << domURI;

    switch (cid)
    {
    case RoutingDomain::CLASS_ID:
        handleRoutingDomainUpdate(domURI);
        break;
    case Subnet::CLASS_ID:
        if (!Subnet::resolve(agent.getFramework(), domURI))
        {
            OLOGD << "Cleaning up for Subnet: " << domURI;
        }
        break;
    case BridgeDomain::CLASS_ID:
        if (!BridgeDomain::resolve(agent.getFramework(), domURI))
        {
            OLOGD << "Cleaning up for BD: " << domURI;
            m_id_gen.erase(cid, domURI);
        }
        break;
    case FloodDomain::CLASS_ID:
        if (!FloodDomain::resolve(agent.getFramework(), domURI))
        {
            OLOGD << "Cleaning up for FD: " << domURI;
            m_id_gen.erase(cid, domURI);
        }
        break;
    case FloodContext::CLASS_ID:
        if (!FloodContext::resolve(agent.getFramework(), domURI))
        {
            OLOGD << "Cleaning up for FloodContext: " << domURI;
        }
        break;
    case L3ExternalNetwork::CLASS_ID:
        if (!L3ExternalNetwork::resolve(agent.getFramework(), domURI))
        {
            OLOGD << "Cleaning up for L3ExtNet: " << domURI;
            m_id_gen.erase(cid, domURI);
        }
        break;
    }
}

void VppManager::handleInterfaceEvent(VOM::interface_cmds::events_cmd *e)
{
    OLOGD << "Interface Event: " << *e;
    if (stopping) return;

    std::lock_guard<VOM::interface_cmds::events_cmd> lg(*e);

    for (auto &msg : *e)
    {
        auto &payload = msg.get_payload();

        VOM::handle_t handle(payload.sw_if_index);
        shared_ptr<VOM::interface> sp = VOM::interface::find(handle);

        if (sp)
        {
            VOM::interface::oper_state_t oper_state =
                VOM::interface::oper_state_t::from_int(payload.link_up_down);

            OLOGD << "Interface Event: " << sp->to_string()
                  << " state: " << oper_state.to_string();

            sp->set(oper_state);
        }
    }

    e->flush();
}

void VppManager::getGroupVnid(const unordered_set<URI> &uris,
                              unordered_set<uint32_t> &ids)
{
    /* opflexagent::PolicyManager &pm = agent.getPolicyManager(); */
    /* for (auto &u : uris) */
    /* { */
    /*     boost::optional<uint32_t> vnid = pm.getVnidForGroup(u); */
    /*     boost::optional<std::shared_ptr<RoutingDomain>> rd; */
    /*     if (vnid) */
    /*     { */
    /*         rd = pm.getRDForGroup(u); */
    /*     } */
    /*     else */
    /*     { */
    /*         rd = pm.getRDForL3ExtNet(u); */
    /*         if (rd) */
    /*         { */
    /*             vnid = getExtNetVnid(u); */
    /*         } */
    /*     } */
    /*     if (vnid && rd) */
    /*     { */
    /*         ids.insert(vnid.get()); */
    /*     } */
    /* } */
}
uint32_t VppManager::getExtNetVnid(const opflex::modb::URI &uri)
{
    // External networks are assigned private VNIDs that have bit 31 (MSB)
    // set to 1. This is fine because legal VNIDs are 24-bits or less.
    return (m_id_gen.get(L3ExternalNetwork::CLASS_ID, uri) | (1 << 31));
}

/* std::shared_ptr<gbp_endpoint_group> */
/* VppManager::getEndPointGroup(const std::string &uuid, const URI &epgURI) */
/* { */
/*     uint32_t epgVnid, rdId, bdId; */
/*     optional<URI> bdURI, rdURI; */
/*     if (!getGroupForwardingInfo(epgURI, epgVnid, rdURI, rdId, bdURI, bdId))
 */
/*     { */
/*         return {}; */
/*     } */

/*     route_domain rd(rdId); */
/*     OM::write(uuid, rd); */
/*     bridge_domain bd(bdId, VOM::bridge_domain::learning_mode_t::OFF); */
/*     OM::write(uuid, bd); */

/*     /\* */
/*      * VOM GBP Endpoint Group */
/*      *\/ */
/*     shared_ptr<VOM::interface> encap_link = */
/*         m_uplink.mk_interface(uuid, epgVnid); */
/*     gbp_endpoint_group gepg(epgVnid, *encap_link, rd, bd); */
/*     OM::write(uuid, gepg); */

/*     return gepg.singular(); */
/* } */

void VppManager::handleContractUpdate(const opflex::modb::URI &contractURI)
{
    /* OLOGD << "Updating contract " << contractURI; */
    /* if (stopping) return; */

    /* const string &uuid = contractURI.toString(); */

    /* VOM::OM::mark_n_sweep ms(uuid); */

    /* PolicyManager &polMgr = agent.getPolicyManager(); */
    /* if (!polMgr.contractExists(contractURI)) */
    /* { */
    /*     // Contract removed */
    /*     return; */
    /* } */

    /* PolicyManager::uri_set_t provURIs; */
    /* PolicyManager::uri_set_t consURIs; */
    /* PolicyManager::uri_set_t intraURIs; */
    /* polMgr.getContractProviders(contractURI, provURIs); */
    /* polMgr.getContractConsumers(contractURI, consURIs); */
    /* polMgr.getContractIntra(contractURI, intraURIs); */

    /* typedef unordered_set<uint32_t> id_set_t; */
    /* id_set_t provIds; */
    /* id_set_t consIds; */
    /* id_set_t intraIds; */
    /* getGroupVnid(provURIs, provIds); */
    /* getGroupVnid(consURIs, consIds); */

    /* PolicyManager::rule_list_t rules; */
    /* polMgr.getContractRules(contractURI, rules); */

    /* for (const uint32_t &pvnid : provIds) */
    /* { */
    /*     for (const uint32_t &cvnid : consIds) */
    /*     { */
    /*         if (pvnid == cvnid) /\* intra group is allowed by default *\/ */
    /*             continue; */

    /*         OLOGD << "Contract prov:" << pvnid << " cons:" << cvnid; */

    /*         /\* */
    /*          * At this point we are implementing only the neutron virtual */
    /*          * router concept. So we use a permit any-any rule and rely */
    /*          * only on the GDBP EPG restructions */
    /*          *\/ */
    /*         VOM::ACL::l3_rule rule(0, VOM::ACL::action_t::PERMIT, */
    /*                                route::prefix_t::ZERO, */
    /*                                route::prefix_t::ZERO); */

    /*         VOM::ACL::l3_list acl(uuid, {rule}); */
    /*         VOM::OM::write(uuid, acl); */

    /*         VOM::gbp_contract gbpc(pvnid, cvnid, acl); */
    /*         VOM::OM::write(uuid, gbpc); */
    /*     } */
    /* } */
}

void VppManager::initPlatformConfig()
{

    using namespace modelgbp::platform;

    optional<shared_ptr<Config>> config = Config::resolve(
        agent.getFramework(), agent.getPolicyManager().getOpflexDomain());
}

void VppManager::handleConfigUpdate(const opflex::modb::URI &configURI)
{
    OLOGD << "Updating platform config " << configURI;
    if (stopping) return;

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

void VppManager::handlePortStatusUpdate(const string &portName, uint32_t)
{
    OLOGD << "Port-status update for " << portName;
    if (stopping) return;
}

Uplink &VppManager::uplink()
{
    return m_uplink;
}
CrossConnect &VppManager::crossConnect()
{
    return m_xconnect;
}

void VppManager::handleSecGrpUpdate(const opflex::modb::URI &uri)
{
    if (stopping) return;
    unordered_set<uri_set_t> secGrpSets;
    agent.getEndpointManager().getSecGrpSetsForSecGrp(uri, secGrpSets);
    for (const uri_set_t &secGrpSet : secGrpSets)
        secGroupSetUpdated(secGrpSet);
}

void VppManager::handleSecGrpSetUpdate(const uri_set_t &secGrps)
{
    /*    OLOGD << "Updating security group set";
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

                VOM::ACL::l3_binding in_binding(direction_t::INPUT, *itf,
       inAcl);
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
