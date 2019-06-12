/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <opflexagent/logging.h>

#include "vom/arp_proxy_binding.hpp"
#include "vom/arp_proxy_config.hpp"
#include "vom/bond_interface.hpp"
#include "vom/bond_member.hpp"
#include "vom/interface.hpp"
#include "vom/ip_punt_redirect.hpp"
#include "vom/ip_unnumbered.hpp"
#include "vom/l3_binding.hpp"
#include "vom/lldp_binding.hpp"
#include "vom/lldp_global.hpp"
#include "vom/neighbour.hpp"
#include "vom/sub_interface.hpp"
#include <vom/bond_group_binding.hpp>

#include "VppSpineProxy.hpp"
#include "VppUplink.hpp"
#include "VppUtil.hpp"

using namespace VOM;

namespace VPP
{

static const std::string UPLINK_KEY = "__uplink__";

Uplink::Uplink(opflexagent::Agent &agent)
    : m_type(VLAN)
    , m_agent(agent)
{
}

const std::string &
Uplink::system_name() const
{
    return m_system_name;
}

std::shared_ptr<VOM::interface>
Uplink::mk_interface(const std::string &uuid, uint32_t vnid)
{
    std::shared_ptr<VOM::interface> sp;
    switch (m_type)
    {
    case VXLAN:
    {
        vxlan_tunnel vt(m_vxlan.src, m_vxlan.dst, vnid);
        VOM::OM::write(uuid, vt);

        return vt.singular();
    }
    case VLAN:
    {
        sub_interface sb(*m_uplink, interface::admin_state_t::UP, vnid);
        VOM::OM::write(uuid, sb);

        return sb.singular();
    }
    }

    return sp;
}

void
Uplink::configure_tap(const route::prefix_t &pfx)
{

    /**
     * Create a tap interface with a fixed mac so we can add a
     * ARP entry for it
     */
    mac_address_t tap_mac("00:00:de:ad:be:ef");

    tap_interface itf("tap0", interface::admin_state_t::UP, pfx, tap_mac);
    VOM::OM::write(UPLINK_KEY, itf);

    neighbour::flags_t f =
        (neighbour::flags_t::STATIC | neighbour::flags_t::NO_FIB_ENTRY);

    neighbour tap_nbr(itf, pfx.address(), tap_mac, f);
    VOM::OM::write(UPLINK_KEY, tap_nbr);

    /*
     * commit and L3 Config to the OM so this uplink owns the
     * subnet on the interface. If we don't have a representation
     * of the configured prefix in the OM, we'll sweep it from the
     * interface if we restart
     */
    l3_binding l3(*m_subitf, pfx);
    OM::commit(UPLINK_KEY, l3);

    ip_unnumbered ipUnnumber(itf, *m_subitf);
    VOM::OM::write(UPLINK_KEY, ipUnnumber);

    arp_proxy_config arpProxyConfig(pfx.low().address().to_v4(),
                                    pfx.high().address().to_v4());
    VOM::OM::write(UPLINK_KEY, arpProxyConfig);

    arp_proxy_binding arpProxyBinding(itf);
    VOM::OM::write(UPLINK_KEY, arpProxyBinding);

    ip_punt_redirect ipPunt(*m_subitf, itf, pfx.address());
    VOM::OM::write(UPLINK_KEY, ipPunt);
}

void
Uplink::handle_dhcp_event(std::shared_ptr<VOM::dhcp_client::lease_t> lease)
{
    m_agent.getAgentIOService().dispatch(
        bind(&Uplink::handle_dhcp_event_i, this, lease));
}

void
Uplink::handle_dhcp_event_i(std::shared_ptr<dhcp_client::lease_t> lease)
{
    LOG(opflexagent::INFO) << "DHCP Event: " << lease->to_string();

    m_pfx = lease->host_prefix;

    /*
     * Create the TAP interface with the DHCP learn address.
     *  This allows all traffic punt to VPP to arrive at the TAP/agent.
     */
    configure_tap(m_pfx);

    /*
     * VXLAN tunnels use the DHCP address as the source
     */
    m_vxlan.src = m_pfx.address();
}

std::shared_ptr<SpineProxy>
Uplink::spine_proxy()
{
    switch (m_agent.getRendererForwardingMode())
    {
    case opflex::ofcore::OFConstants::STITCHED_MODE:
        break;
    case opflex::ofcore::OFConstants::TRANSPORT_MODE:
    {
        boost::asio::ip::address_v4 v4, v6, mac;

        m_agent.getV4Proxy(v4);
        m_agent.getV6Proxy(v6);
        m_agent.getMacProxy(mac);

        return std::make_shared<SpineProxy>(
            local_address().to_v4(), v4, v6, mac);
        break;
    }
    }
    return {};
}

const boost::asio::ip::address &
Uplink::local_address() const
{
    return m_pfx.address();
}

const std::string
Uplink::uplink_l2_address() const
{
    const std::string str("");
    if (m_uplink)
    {
        return m_uplink->l2_address().to_string();
    }
    return str;
}

const std::shared_ptr<interface>
Uplink::local_interface() const
{
    return m_subitf;
}

void
Uplink::configure(const std::string &fqdn)
{
    m_system_name = fqdn;

    LOG(opflexagent::INFO) << "configure:" << m_system_name;

    /*
     * Consruct the uplink physical, so we now 'own' it
     */
    VOM::interface::type_t type = getIntfTypeFromName(m_iface);
    if (VOM::interface::type_t::BOND == type)
    {
        bond_interface bitf(m_iface,
                            interface::admin_state_t::UP,
                            bond_interface::mode_t::LACP,
                            bond_interface::lb_t::L2);
        OM::write(UPLINK_KEY, bitf);
        bond_group_binding::enslaved_itf_t slave_itfs;
        for (auto sif : slave_ifaces)
        {
            interface sitf(
                sif, getIntfTypeFromName(sif), interface::admin_state_t::UP);
            OM::write(UPLINK_KEY, sitf);
            bond_member bm(
                sitf, bond_member::mode_t::ACTIVE, bond_member::rate_t::SLOW);
            slave_itfs.insert(bm);
        }
        if (!slave_itfs.empty())
        {
            bond_group_binding bgb(bitf, slave_itfs);
            OM::write(UPLINK_KEY, bgb);
        }
        m_uplink = bitf.singular();
    }
    else
    {
        interface itf(m_iface, type, interface::admin_state_t::UP);
        OM::write(UPLINK_KEY, itf);
        m_uplink = itf.singular();
    }

    /*
     * Own the v4 and v6 global tables
     */
    route_domain v4_gbl(0);
    OM::write(UPLINK_KEY, v4_gbl);
    route_domain v6_gbl(0);
    OM::write(UPLINK_KEY, v6_gbl);

    /**
     * Enable LLDP on this uplionk
     */
    lldp_global lg(m_system_name, 5, 2);
    OM::write(UPLINK_KEY, lg);
    lldp_binding lb(*m_uplink, "uplink-interface");
    OM::write(UPLINK_KEY, lb);

    /*
     * now create the sub-interface on which control and data traffic from
     * the upstream leaf will arrive
     */
    sub_interface subitf(*m_uplink, interface::admin_state_t::UP, m_vlan);
    OM::write(UPLINK_KEY, subitf);
    m_subitf = subitf.singular();

    /**
     * Strip the fully qualified domain name of any domain name
     * to get just the hostname.
     */
    std::string hostname = fqdn;
    std::string::size_type n = hostname.find(".");
    if (n != std::string::npos)
    {
        hostname = hostname.substr(0, n);
    }

    /**
     * Configure DHCP on the uplink subinterface
     * We must use the MAC address of the uplink interface as the DHCP client-ID
     */
    dhcp_client dc(*m_subitf, hostname, m_uplink->l2_address(), true, this);
    OM::write(UPLINK_KEY, dc);

    /**
     * In the case of a agent restart, the DHCP process will already be complete
     * in VPP and we won't get notified. So check here if the DHCP lease
     * is already aquired.
     */
    std::shared_ptr<dhcp_client::lease_t> lease = dc.singular()->lease();

    if (lease && lease->state != dhcp_client::state_t::DISCOVER)
    {
        LOG(opflexagent::INFO) << "DHCP present: " << lease->to_string();
        configure_tap(lease->host_prefix);
        m_vxlan.src = lease->host_prefix.address();
        m_pfx = lease->host_prefix;
    }
    else
    {
        LOG(opflexagent::DEBUG) << "DHCP awaiting lease";
    }
}

void
Uplink::set(const std::string &uplink,
            uint16_t uplink_vlan,
            const std::string &encap_name,
            const boost::asio::ip::address &remote_ip,
            uint16_t port)
{
    m_type = VXLAN;
    m_vxlan.dst = remote_ip;
    m_iface = uplink;
    m_vlan = uplink_vlan;
}

void
Uplink::set(const std::string &uplink,
            uint16_t uplink_vlan,
            const std::string &encap_name)
{
    m_type = VLAN;
    m_iface = uplink;
    m_vlan = uplink_vlan;
}

void
Uplink::insert_slave_ifaces(std::string name)
{
    this->slave_ifaces.insert(name);
}

void
Uplink::insert_dhcp_options(std::string name)
{
    this->dhcp_options.insert(name);
}
} // namespace VPP

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */
