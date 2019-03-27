/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <boost/optional.hpp>

#include <modelgbp/gbp/L3ExternalDomain.hpp>
#include <modelgbp/gbp/L3ExternalNetwork.hpp>
#include <modelgbp/gbp/RoutingDomain.hpp>
#include <modelgbp/gbp/StaticRoute.hpp>
#include <modelgbp/gbp/RemoteRoute.hpp>

#include <opflexagent/RDConfig.h>

#include <vom/bridge_domain.hpp>
#include <vom/gbp_contract.hpp>
#include <vom/gbp_endpoint.hpp>
#include <vom/gbp_endpoint_group.hpp>
#include <vom/gbp_recirc.hpp>
#include <vom/gbp_subnet.hpp>
#include <vom/gbp_route_domain.hpp>
#include <vom/interface.hpp>
#include <vom/l2_binding.hpp>
#include <vom/l3_binding.hpp>
#include <vom/nat_binding.hpp>
#include <vom/om.hpp>
#include <vom/om.hpp>
#include <vom/route.hpp>
#include <vom/route_domain.hpp>
#include <vom/sub_interface.hpp>
#include <vom/neighbour.hpp>

#include "VppEndPointGroupManager.hpp"
#include "VppLog.hpp"
#include "VppRouteManager.hpp"

using namespace VOM;

namespace VPP
{
RouteManager::RouteManager(Runtime &runtime)
    : m_runtime(runtime)
{
}

opflexagent::network::subnets_t
get_rd_subnets(opflexagent::Agent &agent, const opflex::modb::URI &uri)
{
    /*
     * this is a cut-n-paste from IntflowManager.
     */
    opflexagent::network::subnets_t intSubnets;

    boost::optional<std::shared_ptr<modelgbp::gbp::RoutingDomain>> rd =
        modelgbp::gbp::RoutingDomain::resolve(agent.getFramework(), uri);

    if (!rd)
    {
        return intSubnets;
    }

    std::vector<std::shared_ptr<modelgbp::gbp::RoutingDomainToIntSubnetsRSrc>>
        subnets_list;
    rd.get()->resolveGbpRoutingDomainToIntSubnetsRSrc(subnets_list);
    for (auto &subnets_ref : subnets_list)
    {
        boost::optional<opflex::modb::URI> subnets_uri =
            subnets_ref->getTargetURI();
        opflexagent::PolicyManager::resolveSubnets(
            agent.getFramework(), subnets_uri, intSubnets);
    }
    std::shared_ptr<const opflexagent::RDConfig> rdConfig =
        agent.getExtraConfigManager().getRDConfig(uri);
    if (rdConfig)
    {
        for (const std::string &cidrSn : rdConfig->getInternalSubnets())
        {
            opflexagent::network::cidr_t cidr;
            if (opflexagent::network::cidr_from_string(cidrSn, cidr))
            {
                intSubnets.insert(
                    make_pair(cidr.first.to_string(), cidr.second));
            }
            else
            {
                VLOGE << "Invalid CIDR subnet: " << cidrSn;
            }
        }
    }

    return intSubnets;
}

void
RouteManager::mk_ext_nets(Runtime &runtime,
                          route_domain &rd,
                          const opflex::modb::URI &uri,
                          std::shared_ptr<modelgbp::gbp::L3ExternalDomain> ext_dom)
{
    const std::string &uuid = uri.toString();

    /* To get all the external networks in an external domain */
    std::vector<std::shared_ptr<modelgbp::gbp::L3ExternalNetwork>> ext_nets;
    ext_dom->resolveGbpL3ExternalNetwork(ext_nets);

    for (std::shared_ptr<modelgbp::gbp::L3ExternalNetwork> net : ext_nets)
    {
        const opflex::modb::URI net_uri = net->getURI();

        /* For each external network, get the sclass */
        boost::optional<uint32_t> sclass =
            runtime.policy_manager().getSclassForExternalNet(net_uri);

        if (!sclass)
        {
            VLOGI << "External-Network; no sclass: " << net_uri;
            continue;
        }

        /* traverse each subnet in the network */
        std::vector<std::shared_ptr<modelgbp::gbp::ExternalSubnet>> ext_subs;
        net->resolveGbpExternalSubnet(ext_subs);

        for (std::shared_ptr<modelgbp::gbp::ExternalSubnet> snet : ext_subs)
        {
            VLOGD << "External-Interface; subnet:" << uri
                  << " external:" << ext_dom.get()->getName("n/a")
                  << " external-net:" << net->getName("n/a")
                  << " external-sub:" << snet->getAddress("n/a") << "/"
                  << std::to_string(snet->getPrefixLen(99))
                  << " sclass:" << sclass.get();

            if (!snet->isAddressSet() || !snet->isPrefixLenSet())
                    continue;

            boost::asio::ip::address addr =
                boost::asio::ip::address::from_string(snet->getAddress().get());

            gbp_subnet gs(rd, {addr, snet->getPrefixLen().get()}, sclass.get());
            OM::write(uuid, gs);
        }
    }
}

void
RouteManager::handle_domain_update(const opflex::modb::URI &uri)
{
    OM::mark_n_sweep ms(uri.toString());

    boost::optional<std::shared_ptr<modelgbp::gbp::RoutingDomain>> op_opf_rd =
        modelgbp::gbp::RoutingDomain::resolve(m_runtime.agent.getFramework(),
                                              uri);

    if (!op_opf_rd)
    {
        VLOGD << "Cleaning up for RD: " << uri;
        m_runtime.id_gen.erase(modelgbp::gbp::RoutingDomain::CLASS_ID, uri);
        return;
    }
    std::shared_ptr<modelgbp::gbp::RoutingDomain> opf_rd = op_opf_rd.get();

    const std::string &rd_uuid = uri.toString();

    VLOGD << "Importing routing domain:" << uri;

    /*
     * get all the subnets that are internal to this route domain
     */
    opflexagent::network::subnets_t intSubnets =
        get_rd_subnets(m_runtime.agent, uri);
    boost::system::error_code ec;

    /*
     * create (or at least own) VPP's route-domain object
     */
    uint32_t rdId =
        m_runtime.id_gen.get(modelgbp::gbp::RoutingDomain::CLASS_ID, uri);

    VOM::route_domain rd(rdId);
    VOM::OM::write(rd_uuid, rd);
    VOM::gbp_route_domain grd(rd);
    VOM::OM::write(rd_uuid, grd);

    /*
     * For each internal Subnet
     */
    for (const auto &sn : intSubnets)
    {
        /*
         * still a little more song and dance before we can get
         * our hands on an address ...
         */
        boost::asio::ip::address addr =
            boost::asio::ip::address::from_string(sn.first, ec);
        if (ec) continue;

        VLOGD << "Importing routing domain:" << uri << " subnet:" << addr << "/"
              << std::to_string(sn.second);

        /*
         * add a route for the subnet in VPP's route-domain via
         * the EPG's uplink, DVR styleee
         */
        gbp_subnet gs(rd, {addr, sn.second},
                      (m_runtime.is_transport_mode ?
                       gbp_subnet::type_t::TRANSPORT :
                       gbp_subnet::type_t::STITCHED_INTERNAL));
        OM::write(rd_uuid, gs);
    }

    /*
     * for each external subnet
     */
    std::vector<std::shared_ptr<modelgbp::gbp::L3ExternalDomain>> extDoms;
    opf_rd.get()->resolveGbpL3ExternalDomain(extDoms);

    for (std::shared_ptr<modelgbp::gbp::L3ExternalDomain> ext_dom : extDoms)
    {
        mk_ext_nets(m_runtime, rd, uri, ext_dom);
    }
}

void
RouteManager::handle_route_update(const opflex::modb::URI &uri)
{
    const std::string &uuid = uri.toString();

    OM::mark_n_sweep ms(uuid);

    boost::optional<std::shared_ptr<modelgbp::epdr::LocalRoute>> op_local_route =
        modelgbp::epdr::LocalRoute::resolve(m_runtime.agent.getFramework(), uri);

    if (!op_local_route)
    {
        VLOGD << "Cleaning up for Route: " << uri;
        return;
    }

    mac_address_t GBP_ROUTED_DST_MAC("00:0c:0c:0c:0c:0c");

    std::shared_ptr<modelgbp::gbp::RoutingDomain> rd;
    std::shared_ptr<modelgbp::gbpe::InstContext> rd_inst;
    boost::asio::ip::address pfx_addr;
    uint8_t pfx_len;
    std::list<boost::asio::ip::address> nh_list;
    bool are_nhs_remote;
    boost::optional<uint32_t> sclass;

    m_runtime.agent.getPolicyManager().getRoute
        (modelgbp::epdr::LocalRoute::CLASS_ID, uri,
         m_runtime.uplink.local_address(),
         rd, rd_inst, pfx_addr, pfx_len,
         nh_list, are_nhs_remote, sclass);

    if (!rd)
    {
        VLOGI << "RD not resolved for Route: " << uri;
        return;
    }

    uint32_t rd_id = m_runtime.id_gen.get(modelgbp::gbp::RoutingDomain::CLASS_ID,
                                          rd->getURI());
 
    VOM::route_domain v_rd(rd_id);
    VOM::OM::write(uuid, v_rd);

    route::prefix_t pfx(pfx_addr, pfx_len);
    route::ip_route v_route(v_rd, pfx);

    for (auto nh : nh_list)
    {
        if (are_nhs_remote)
        {
            /*
             * route via vxlan-gbp-tunnel
             */
            vxlan_tunnel vt(m_runtime.uplink.local_address(), nh,
                            rd_inst->getEncapId().get(),
                            v_rd,
                            vxlan_tunnel::mode_t::GBP_L3);
            OM::write(uuid, vt);

            neighbour::flags_t f = (neighbour::flags_t::STATIC |
                                    neighbour::flags_t::NO_FIB_ENTRY);

            neighbour nbr(vt, nh, GBP_ROUTED_DST_MAC, f);
            VOM::OM::write(uuid, nbr);

            v_route.add({nh, vt});
        }
        else
        {
            /*
             * routed via a local next-hop
             */
            v_route.add({v_rd, nh});
        }
    }

    VOM::OM::write(uuid, v_route);

    /* attach the sclass information to the route */
    if (sclass)
    {
        gbp_subnet v_gs(v_rd, pfx, sclass.get());
        VOM::OM::write(uuid, v_gs);
    }
    else
    {
        VLOGW << "No slcass for: " << uri;
    }
}


}; // namepsace VPP

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */
