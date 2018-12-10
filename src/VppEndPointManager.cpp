/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2017-2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <opflexagent/Endpoint.h>
#include <opflexagent/EndpointManager.h>
#include <opflexagent/logging.h>

#include <modelgbp/gbp/RoutingModeEnumT.hpp>
#include <modelgbp/l2/EtherTypeEnumT.hpp>

#include <vom/acl_binding.hpp>
#include <vom/acl_ethertype.hpp>
#include <vom/bridge_domain.hpp>
#include <vom/bridge_domain_arp_entry.hpp>
#include <vom/bridge_domain_entry.hpp>
#include <vom/gbp_contract.hpp>
#include <vom/gbp_endpoint.hpp>
#include <vom/gbp_endpoint_group.hpp>
#include <vom/gbp_recirc.hpp>
#include <vom/gbp_subnet.hpp>
#include <vom/l2_binding.hpp>
#include <vom/l3_binding.hpp>
#include <vom/nat_binding.hpp>
#include <vom/nat_static.hpp>
#include <vom/neighbour.hpp>
#include <vom/om.hpp>
#include <vom/route.hpp>
#include <vom/route_domain.hpp>
#include <vom/sub_interface.hpp>
#include <vom/stat_reader.hpp>

#include "VppEndPointGroupManager.hpp"
#include "VppEndPointManager.hpp"
#include "VppLog.hpp"
#include "VppSecurityGroupManager.hpp"
#include "VppUtil.hpp"

using namespace VOM;
using namespace boost;

namespace VPP
{
EndPointManager::EndPointManager(opflexagent::Agent &agent,
                                 IdGen &id_gen,
                                 Uplink &uplink,
                                 std::shared_ptr<VirtualRouter> vr)
    : m_agent(agent)
    , m_id_gen(id_gen)
    , m_uplink(uplink)
    , m_vr(vr)
{
}

EndPointManager::~EndPointManager()
{
}

std::string
EndPointManager::get_ep_interface_name(const opflexagent::Endpoint &ep) throw(
    NoEpInterfaceException)
{
    const optional<std::string> &epAccessItf = ep.getAccessInterface();
    const optional<std::string> &epItf = ep.getInterfaceName();
    const std::string uuid = ep.getUUID();
    std::string iname;

    /*
     * the goal here is to get the name of the interface to which the VM
     * is attached.
     */
    if (epAccessItf)
        iname = epAccessItf.get();
    else if (epItf)
        iname = epItf.get();
    else
        throw NoEpInterfaceException();

    return iname;
}

std::shared_ptr<interface>
EndPointManager::mk_bd_interface(
    const opflexagent::Endpoint &ep,
    const bridge_domain &bd,
    const route_domain &rd) throw(NoEpInterfaceException)
{
    const optional<std::string> &epAccessItf = ep.getAccessInterface();
    const optional<std::string> &epItf = ep.getInterfaceName();
    const std::string uuid = ep.getUUID();
    std::string iname = get_ep_interface_name(ep);
    std::shared_ptr<interface> itf;

    if (ep.getAccessIfaceVlan())
    {
        uint16_t vlan_id;
        interface intf(iname,
                       getIntfTypeFromName(iname),
                       interface::admin_state_t::UP,
                       uuid);
        OM::write(uuid, intf);

        vlan_id = ep.getAccessIfaceVlan().get();
        sub_interface sub_itf(intf, interface::admin_state_t::UP, rd, vlan_id);
        OM::write(uuid, sub_itf);
        itf = sub_itf.singular();

        /*
         * EP's interface is in the EPG's BD
         */
        l2_binding l2itf(*itf, bd);
        if (ep.getAccessIfaceVlan())
        {
            l2itf.set(l2_binding::l2_vtr_op_t::L2_VTR_POP_1, vlan_id);
        }

        OM::write(uuid, l2itf);
    }
    else
    {
        interface intf(iname,
                       getIntfTypeFromName(iname),
                       interface::admin_state_t::UP,
                       rd,
                       uuid);
        OM::write(uuid, intf);
        itf = intf.singular();
    }

    /*
     * If the interface is not created then we cannot do anymore
     */
    if (handle_t::INVALID == itf->handle()) throw NoEpInterfaceException();

    return itf;
}

static void
allow_dhcp_request(ACL::l3_list::rules_t &in_rules,
                   ACL::l3_list::rules_t &out_rules,
                   uint16_t etherType)
{

    ACL::action_t act = ACL::action_t::PERMIT;

    if (etherType == modelgbp::l2::EtherTypeEnumT::CONST_IPV4)
    {
        route::prefix_t pfx = route::prefix_t::ZERO;

        ACL::l3_rule rule(200, act, pfx, pfx);

        rule.set_proto(17);
        rule.set_src_from_port(68);
        rule.set_src_to_port(68);
        rule.set_dst_from_port(67);
        rule.set_dst_to_port(67);

        in_rules.insert(rule);

        ACL::l3_rule out_rule(200, act, pfx, pfx);

        out_rule.set_proto(17);
        out_rule.set_src_from_port(67);
        out_rule.set_src_to_port(67);
        out_rule.set_dst_from_port(68);
        out_rule.set_dst_to_port(68);

        out_rules.insert(out_rule);
    }
    else
    {
        route::prefix_t pfx = route::prefix_t::ZEROv6;

        ACL::l3_rule rule(200, act, pfx, pfx);

        rule.set_proto(17);
        rule.set_src_from_port(546);
        rule.set_src_to_port(546);
        rule.set_dst_from_port(547);
        rule.set_dst_to_port(547);

        in_rules.insert(rule);

        ACL::l3_rule out_rule(200, act, pfx, pfx);

        out_rule.set_proto(17);
        out_rule.set_src_from_port(547);
        out_rule.set_src_to_port(547);
        out_rule.set_dst_from_port(546);
        out_rule.set_dst_to_port(546);

        out_rules.insert(out_rule);
    }
}

static std::vector<asio::ip::address>
get_ep_ips(const opflexagent::Endpoint &ep)
{
    /* check and parse the IP-addresses */
    system::error_code ec;
    std::vector<asio::ip::address> ipAddresses;

    const optional<opflex::modb::MAC> mac = ep.getMAC();

    for (const std::string &ipStr : ep.getIPs())
    {
        asio::ip::address addr = asio::ip::address::from_string(ipStr, ec);
        if (ec)
        {
            LOG(opflexagent::WARNING) << "Invalid endpoint IP: " << ipStr
                                      << ": " << ec.message();
        }
        else
        {
            ipAddresses.push_back(addr);
        }
    }

    if (mac)
    {
        asio::ip::address_v6 linkLocalIp(
            opflexagent::network::construct_link_local_ip_addr(mac.get()));
        if (ep.getIPs().find(linkLocalIp.to_string()) == ep.getIPs().end())
            ipAddresses.push_back(linkLocalIp);
    }

    return ipAddresses;
}

void
EndPointManager::handle_interface_stat_i(const interface& itf)
{
    VLOGD << "Interface Stat: " << itf.to_string();

    opflexagent::EndpointManager &epMgr = m_agent.getEndpointManager();

    opflexagent::EndpointManager::EpCounters counters;
    std::unordered_set<std::string> endpoints;
    auto &data = itf.get_stats();

    VLOGD << "Stats data: " << data;

    epMgr.getEndpointsByAccessIface(itf.name(), endpoints);

    memset(&counters, 0, sizeof(counters));
    counters.txPackets = data.m_tx.packets;
    counters.rxPackets = data.m_rx.packets;
    counters.txBytes = data.m_tx.bytes;
    counters.rxBytes = data.m_rx.bytes;
    counters.rxUnicast = data.m_rx_unicast.packets;
    counters.txUnicast = data.m_tx_unicast.packets;
    counters.rxBroadcast = data.m_rx_broadcast.packets;
    counters.txBroadcast = data.m_tx_broadcast.packets;
    counters.rxMulticast = data.m_rx_multicast.packets;
    counters.txMulticast = data.m_tx_multicast.packets;
    // counters.txDrop = data.tx_dropped;
    // counters.rxDrop = data.rx_dropped;

    for (const std::string &uuid : endpoints)
    {
        if (counters.rxDrop == std::numeric_limits<uint64_t>::max())
            counters.rxDrop = 0;
        if (counters.txDrop == std::numeric_limits<uint64_t>::max())
            counters.txDrop = 0;
        if (counters.txPackets == std::numeric_limits<uint64_t>::max())
            counters.txPackets = 0;
        if (counters.rxPackets == std::numeric_limits<uint64_t>::max())
            counters.rxPackets = 0;
        if (counters.txBroadcast ==
            std::numeric_limits<uint64_t>::max())
            counters.txBroadcast = 0;
        if (counters.rxBroadcast ==
            std::numeric_limits<uint64_t>::max())
            counters.rxBroadcast = 0;
        if (counters.txMulticast ==
            std::numeric_limits<uint64_t>::max())
            counters.txMulticast = 0;
        if (counters.rxMulticast ==
            std::numeric_limits<uint64_t>::max())
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

void
EndPointManager::handle_interface_stat(const interface& itf)
{
    handle_interface_stat_i(itf);
}

void
EndPointManager::handle_update(const std::string &uuid)
{
    /*
     * This is an update to all the state related to this endpoint.
     * At the end of processing we want all the state related to this endpint,
     * that we don't touch here, gone.
     */
    OM::mark_n_sweep ms(uuid);
    system::error_code ec;
    int rv;

    opflexagent::EndpointManager &epMgr = m_agent.getEndpointManager();
    std::shared_ptr<const opflexagent::Endpoint> epWrapper =
        epMgr.getEndpoint(uuid);

    if (!epWrapper)
    {
        VLOGD << "Deleting endpoint " << uuid;
        return;
    }
    VLOGD << "Updating endpoint " << uuid;

    optional<opflex::modb::URI> epgURI = epMgr.getComputedEPG(uuid);

    if (!epgURI)
    {
        // can't do much without EPG
        VLOGD << "Endpoint - no EPG " << uuid;
        return;
    }

    EndPointGroupManager::ForwardInfo fwd;

    try
    {
        fwd =
            EndPointGroupManager::get_fwd_info(m_agent, m_id_gen, epgURI.get());

        /*
         * the route-domain the endpoint is in.
         */
        route_domain rd(fwd.rdId);
        OM::write(uuid, rd);
        bridge_domain bd(fwd.bdId, bridge_domain::learning_mode_t::OFF);
        OM::write(uuid, bd);

        std::shared_ptr<SpineProxy> spine_proxy =
            m_uplink.spine_proxy(fwd.vnid);

        /*
         * VOM GBP Endpoint Group
         */
        std::shared_ptr<interface> encap_link =
            m_uplink.mk_interface(epgURI.get().toString(), fwd.vnid);
        gbp_endpoint_group gepg(fwd.vnid, *encap_link, rd, bd);
        OM::write(uuid, gepg);

        /*
         * We want a veth interface - admin up
         */
        std::shared_ptr<interface> itf;
        try
        {
            const opflexagent::Endpoint &ep = *epWrapper.get();

            itf = mk_bd_interface(ep, bd, rd);

            /**
             * We are interested in getting detailed interface stats from VPP
             */
            itf->enable_stats(this);

            /*
             * Apply Security Groups
             */
            const opflexagent::EndpointListener::uri_set_t &secGrps =
                ep.getSecurityGroups();
            const std::string secGrpId = SecurityGroupManager::get_id(secGrps);
            hash<std::string> string_hash;
            const std::string secGrpKey = std::to_string(string_hash(secGrpId));

            ACL::l3_list::rules_t in_rules, out_rules;
            ACL::acl_ethertype::ethertype_rules_t ethertype_rules;

            optional<opflexagent::Endpoint::DHCPv4Config> v4c =
                ep.getDHCPv4Config();
            if (v4c)
            {
                ACL::ethertype_rule_t et(ethertype_t::IPV4, direction_t::INPUT);
                ethertype_rules.insert(et);
                ACL::ethertype_rule_t out_et(ethertype_t::IPV4,
                                             direction_t::OUTPUT);
                ethertype_rules.insert(out_et);
                allow_dhcp_request(in_rules,
                                   out_rules,
                                   modelgbp::l2::EtherTypeEnumT::CONST_IPV4);
            }
            optional<opflexagent::Endpoint::DHCPv6Config> v6c =
                ep.getDHCPv6Config();
            if (v6c)
            {
                ACL::ethertype_rule_t et(ethertype_t::IPV6, direction_t::INPUT);
                ethertype_rules.insert(et);
                ACL::ethertype_rule_t out_et(ethertype_t::IPV6,
                                             direction_t::OUTPUT);
                ethertype_rules.insert(out_et);
                allow_dhcp_request(in_rules,
                                   out_rules,
                                   modelgbp::l2::EtherTypeEnumT::CONST_IPV6);
            }

            SecurityGroupManager::build_update(m_agent,
                                               secGrps,
                                               secGrpId,
                                               in_rules,
                                               out_rules,
                                               ethertype_rules);

            if (!ethertype_rules.empty())
            {
                ACL::acl_ethertype a_e(*itf, ethertype_rules);
                OM::write(uuid, a_e);
            }
            if (!in_rules.empty())
            {
                ACL::l3_list in_acl(secGrpKey + "-in", in_rules);
                OM::write(uuid, in_acl);

                ACL::l3_binding in_binding(direction_t::INPUT, *itf, in_acl);
                OM::write(uuid, in_binding);
            }
            if (!out_rules.empty())
            {
                ACL::l3_list out_acl(secGrpKey + "-out", out_rules);
                OM::write(uuid, out_acl);

                ACL::l3_binding out_binding(direction_t::OUTPUT, *itf, out_acl);
                OM::write(uuid, out_binding);
            }

            uint8_t macAddr[6] = {0};
            bool hasMac = ep.getMAC() != none;

            if (hasMac) ep.getMAC().get().toUIntArray(macAddr);

            /* check and parse the IP-addresses */
            std::vector<asio::ip::address> ipAddresses = get_ep_ips(ep);

            ACL::l2_list::rules_t rules;
            if (itf->handle().value())
            {
                if (ep.isPromiscuousMode())
                {
                    ACL::l2_rule rulev6(50,
                                        ACL::action_t::PERMIT,
                                        route::prefix_t::ZEROv6,
                                        macAddr,
                                        mac_address_t::ZERO);

                    ACL::l2_rule rulev4(51,
                                        ACL::action_t::PERMIT,
                                        route::prefix_t::ZERO,
                                        macAddr,
                                        mac_address_t::ZERO);
                    rules.insert(rulev4);
                    rules.insert(rulev6);
                }
                else if (hasMac)
                {
                    ACL::l2_rule rulev6(20,
                                        ACL::action_t::PERMIT,
                                        route::prefix_t::ZEROv6,
                                        macAddr,
                                        mac_address_t::ONE);

                    ACL::l2_rule rulev4(21,
                                        ACL::action_t::PERMIT,
                                        route::prefix_t::ZERO,
                                        macAddr,
                                        mac_address_t::ONE);
                    rules.insert(rulev4);
                    rules.insert(rulev6);

                    for (auto &ipAddr : ipAddresses)
                    {
                        // Allow IPv4/IPv6 packets from port with EP IP address
                        route::prefix_t pfx(ipAddr, ipAddr.is_v4() ? 32 : 128);
                        if (ipAddr.is_v6())
                        {
                            ACL::l2_rule rule(30,
                                              ACL::action_t::PERMIT,
                                              pfx,
                                              macAddr,
                                              mac_address_t::ONE);
                            rules.insert(rule);
                        }
                        else
                        {
                            ACL::l2_rule rule(31,
                                              ACL::action_t::PERMIT,
                                              pfx,
                                              macAddr,
                                              mac_address_t::ONE);
                            rules.insert(rule);
                        }
                    }
                }

                for (const opflexagent::Endpoint::virt_ip_t &vip :
                     ep.getVirtualIPs())
                {
                    opflexagent::network::cidr_t vip_cidr;
                    if (!opflexagent::network::cidr_from_string(vip.second,
                                                                vip_cidr))
                    {
                        LOG(opflexagent::WARNING)
                            << "Invalid endpoint VIP (CIDR): " << vip.second;
                        continue;
                    }
                    uint8_t vmac[6];
                    vip.first.toUIntArray(vmac);

                    for (auto &ipAddr : ipAddresses)
                    {
                        if (!opflexagent::network::cidr_contains(vip_cidr,
                                                                 ipAddr))
                        {
                            continue;
                        }
                        route::prefix_t pfx(ipAddr, ipAddr.is_v4() ? 32 : 128);
                        if (ipAddr.is_v6())
                        {
                            ACL::l2_rule rule(60,
                                              ACL::action_t::PERMIT,
                                              pfx,
                                              vmac,
                                              mac_address_t::ONE);
                            rules.insert(rule);
                        }
                        else
                        {
                            ACL::l2_rule rule(61,
                                              ACL::action_t::PERMIT,
                                              pfx,
                                              vmac,
                                              mac_address_t::ONE);
                            rules.insert(rule);
                        }
                    }
                }

                ACL::l2_list acl(uuid, rules);
                OM::write(uuid, acl);

                ACL::l2_binding binding(direction_t::INPUT, *itf, acl);
                OM::write(uuid, binding);
            }

            /*
             * Create/get the BVI interface for the EPG
             */
            interface bvi("bvi-" + std::to_string(bd.id()),
                          interface::type_t::BVI,
                          interface::admin_state_t::UP,
                          rd);
            OM::write(uuid, bvi);

            if (hasMac)
            {
                mac_address_t vmac(macAddr);

                /*
                 * add a GDBP endpoint
                 */
                gbp_endpoint gbpe(*itf, ipAddresses, vmac, gepg);
                OM::write(uuid, gbpe);

                /*
                 * Floating IP addresses -> NAT
                 */
                if (m_vr && (modelgbp::gbp::RoutingModeEnumT::CONST_ENABLED ==
                             m_agent.getPolicyManager().getEffectiveRoutingMode(
                                 epgURI.get())))
                {
                    auto ipms = ep.getIPAddressMappings();

                    if (0 != ipms.size())
                    {
                        /*
                         * there are floating IPs, we need a recirulation
                         * interface
                         * for this EP's EPG. These are NAT outside and input
                         * feautre
                         * since packets are sent to these interface in order to
                         * have
                         * the out2in translation applied.
                         */
                        interface recirc_itf("recirc-" +
                                                 std::to_string(fwd.vnid),
                                             interface::type_t::LOOPBACK,
                                             interface::admin_state_t::UP,
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

                        gbp_recirc grecirc(
                            recirc_itf, gbp_recirc::type_t::INTERNAL, gepg);
                        OM::write(uuid, grecirc);

                        for (auto &ipm : ipms)
                        {
                            if (!ipm.getMappedIP() || !ipm.getEgURI()) continue;

                            asio::ip::address mappedIp =
                                asio::ip::address::from_string(
                                    ipm.getMappedIP().get(), ec);
                            if (ec) continue;

                            asio::ip::address floatingIp;
                            if (ipm.getFloatingIP())
                            {
                                floatingIp = asio::ip::address::from_string(
                                    ipm.getFloatingIP().get(), ec);
                                if (ec) continue;
                                if (floatingIp.is_v4() != mappedIp.is_v4())
                                    continue;
                            }

                            EndPointGroupManager::ForwardInfo ffwd;

                            try
                            {
                                ffwd = EndPointGroupManager::get_fwd_info(
                                    m_agent, m_id_gen, ipm.getEgURI().get());

                                VLOGD << "EP:" << uuid << " - add Floating IP"
                                      << floatingIp << " => " << mappedIp;

                                /*
                                 * Route and Bridge Domains and the external EPG
                                 */
                                route_domain ext_rd(ffwd.rdId);
                                OM::write(uuid, ext_rd);
                                bridge_domain ext_bd(
                                    ffwd.bdId,
                                    bridge_domain::learning_mode_t::OFF);
                                OM::write(uuid, ext_bd);
                                interface ext_bvi("bvi-" +
                                                      std::to_string(ffwd.bdId),
                                                  interface::type_t::BVI,
                                                  interface::admin_state_t::UP,
                                                  ext_rd);
                                OM::write(uuid, ext_bvi);

                                /*
                                 * Route for the floating IP via the internal
                                 * EPG's recirc
                                 */
                                route::prefix_t fp_pfx(floatingIp);
                                route::ip_route fp_route(
                                    ext_rd,
                                    fp_pfx,
                                    {recirc_itf,
                                     fp_pfx.l3_proto().to_nh_proto(),
                                     route::path::flags_t::DVR});
                                OM::write(uuid, fp_route);

                                neighbour fp_ne(ext_bvi, floatingIp, {macAddr});
                                OM::write(uuid, fp_ne);

                                /*
                                 * reply to ARP's for the floating IP
                                 */
                                bridge_domain_arp_entry fp_bae(
                                    ext_bd, floatingIp, {macAddr});
                                OM::write(uuid, fp_bae);

                                /*
                                 * Bridge L2 packets addressed to the VM to the
                                 * recirc
                                 * interface
                                 */
                                bridge_domain_entry fp_be(
                                    ext_bd, macAddr, recirc_itf);
                                OM::write(uuid, fp_be);

                                /*
                                 * NAT static mapping
                                 */
                                nat_static ns(rd, mappedIp, floatingIp);
                                OM::write(uuid, ns);
                            }
                            catch (EndPointGroupManager::NoFowardInfoException
                                       &nofwd)
                            {
                                VLOGD << "Endpoint Floating IP no fwd " << uuid;
                            }
                        }
                    }
                }
            }
        }
        catch (EndPointManager::NoEpInterfaceException &noepitf)
        {
            VLOGD << "Endpoint - no interface " << uuid;
        }
    }
    catch (EndPointGroupManager::NoFowardInfoException &nofwd)
    {
        VLOGD << "Endpoint - no fwding " << uuid;
    }

    /*
     * That's all folks ... destructor of mark_n_sweep calls the
     * sweep for the stale state
     */
}

}; // namespace VPP
