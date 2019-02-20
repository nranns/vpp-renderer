/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2017-2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __VPP_UPLINK_H__
#define __VPP_UPLINK_H__

#include <unordered_set>

#include "opflexagent/Agent.h"

#include <vom/dhcp_client.hpp>
#include <vom/tap_interface.hpp>
#include <vom/vxlan_tunnel.hpp>

//#include "VppSpineProxy.hpp"

using namespace VOM;

namespace VPP
{
class SpineProxy;
/**
 * A description of the uplink interface.
 *  Can be one of VLAN< VXLAN or iVXLAN
 */
class Uplink : public dhcp_client::event_listener
{
  public:
    /**
     * The uplink interface's encapsulation type for data traffic.
     */
    enum uplink_type_t
    {
        /**
         * VXLAN encap
         */
        VXLAN,
        /**
         * VLAN encap
         */
        VLAN,
    };

    /**
     * Default Constructor
     */
    Uplink(opflexagent::Agent &agent);

    /**
     * Given the VNID, create an interface of the appropriate type
     */
    std::shared_ptr<interface> mk_interface(const std::string &uuid,
                                            uint32_t vnid);

    /**
     * Set the uplink paramenters for vxlan
     */
    void set(const std::string &uplink,
             uint16_t vlan,
             const std::string &name,
             const boost::asio::ip::address &ip,
             uint16_t port);

    /**
     * Set the uplink paramenters for vlan
     */
    void set(const std::string &uplink, uint16_t vlan, const std::string &name);

    /**
     * make the control channel/interfaces
     *
     * @param fqdn Fully Qualifed Domain name
     */
    void configure(const std::string &fqdn);

    /**
     * insert the new slave interface in the slave_ifaces
     */
    void insert_slave_ifaces(std::string name);

    /**
     * insert the dhcp options
     */
    void insert_dhcp_options(std::string name);

    const boost::asio::ip::address &local_address() const;
    const std::shared_ptr<interface> local_interface() const;

    /**
     * Handle notifications about DHCP complete
     */
    void handle_dhcp_event(std::shared_ptr<dhcp_client::lease_t> lease);

    std::shared_ptr<SpineProxy> spine_proxy();

  private:
    void handle_dhcp_event_i(std::shared_ptr<dhcp_client::lease_t> lease);

    /**
     * Configure the tap interface
     */
    void configure_tap(const route::prefix_t &pfx);

    /**
     * VXLAN uplink encap, if used
     */
    vxlan_tunnel::endpoint_t m_vxlan;

    /**
     * A reference to the uplink physical insterface
     */
    std::shared_ptr<interface> m_uplink;

    /**
     * A reference to the uplink vlan insterface
     */
    std::shared_ptr<interface> m_subitf;

    /**
     * the encap type on the uplinnk
     */
    uplink_type_t m_type;

    /**
     * The VLAN used for control traffic
     */
    uint16_t m_vlan;

    /**
     * The name of the uplink interface
     */
    std::string m_iface;

    /**
     * The name of the slave interfaces (in case of Bond)
     */
    std::unordered_set<std::string> slave_ifaces;

    /**
     * The dhcp options for uplink interface
     */
    std::unordered_set<std::string> dhcp_options;

    /**
     * the uber agent
     */
    opflexagent::Agent &m_agent;

    route::prefix_t m_pfx;
};
};

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */

#endif
