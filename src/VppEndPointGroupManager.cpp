/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <boost/optional.hpp>

#include <opflexagent/Agent.h>
#include <opflexagent/PolicyManager.h>

#include <modelgbp/gbp/BridgeDomain.hpp>
#include <modelgbp/gbp/RoutingDomain.hpp>

#include <vom/bridge_domain.hpp>
#include <vom/bridge_domain_arp_entry.hpp>
#include <vom/bridge_domain_entry.hpp>
#include <vom/gbp_endpoint_group.hpp>
#include <vom/gbp_subnet.hpp>
#include <vom/l2_binding.hpp>
#include <vom/l3_binding.hpp>
#include <vom/nat_binding.hpp>
#include <vom/nat_static.hpp>
#include <vom/neighbour.hpp>
#include <vom/om.hpp>
#include <vom/route_domain.hpp>

#include "VppEndPointGroupManager.hpp"
#include "VppLog.hpp"

namespace VPP
{
EndPointGroupManager::EndPointGroupManager(opflexagent::Agent &agent,
                                           IdGen &id_gen, Uplink &uplink,
                                           std::shared_ptr<VirtualRouter> vr)
    : m_agent(agent)
    , m_id_gen(id_gen)
    , m_uplink(uplink)
    , m_vr(vr)
{
}

EndPointGroupManager::ForwardInfo EndPointGroupManager::get_fwd_info(
    opflexagent::Agent &agent, IdGen &id_gen,
    const opflex::modb::URI &uri) throw(NoFowardInfo)
{
    EndPointGroupManager::ForwardInfo fwd;
    opflexagent::PolicyManager &polMgr = agent.getPolicyManager();
    boost::optional<uint32_t> epgVnid = polMgr.getVnidForGroup(uri);

    if (!epgVnid)
    {
        throw NoFowardInfo();
    }
    fwd.vnid = epgVnid.get();

    boost::optional<std::shared_ptr<modelgbp::gbp::RoutingDomain>> epgRd =
        polMgr.getRDForGroup(uri);
    boost::optional<std::shared_ptr<modelgbp::gbp::BridgeDomain>> epgBd =
        polMgr.getBDForGroup(uri);
    if (!epgBd)
    {
        throw NoFowardInfo();
    }

    if (epgRd)
    {
        fwd.rdURI = epgRd.get()->getURI();
        if (fwd.rdURI)
            fwd.rdId = id_gen.get(modelgbp::gbp::RoutingDomain::CLASS_ID,
                                  fwd.rdURI.get());
    }
    if (epgBd)
    {
        fwd.bdURI = epgBd.get()->getURI();
        fwd.bdId =
            id_gen.get(modelgbp::gbp::BridgeDomain::CLASS_ID, fwd.bdURI.get());
    }
    return fwd;
}

void EndPointGroupManager::handle_update(const opflex::modb::URI &epgURI)
{
    const std::string &epg_uuid = epgURI.toString();

    /*
     * Mark all of this EPG's state stale. this RAII pattern
     * will sweep all state that is not updated.
     */
    OM::mark_n_sweep ms(epg_uuid);

    OLOGD << "Updating endpoint-group:" << epgURI;

    opflexagent::PolicyManager &pm = m_agent.getPolicyManager();

    if (!m_agent.getPolicyManager().groupExists(epgURI))
    {
        OLOGD << "Deleting endpoint-group:" << epgURI;
        return;
    }

    try
    {
        EndPointGroupManager::ForwardInfo fwd;

        fwd = get_fwd_info(m_agent, m_id_gen, epgURI);

        /*
         * Construct the Bridge and routing Domains
         */
        bridge_domain bd(fwd.bdId, bridge_domain::learning_mode_t::OFF);
        OM::write(epg_uuid, bd);
        route_domain rd(fwd.rdId);
        OM::write(epg_uuid, rd);

        /*
         * Construct the encap-link
         */
        std::shared_ptr<interface> encap_link =
            m_uplink.mk_interface(epg_uuid, fwd.vnid);

        /*
         * GBP Endpoint Group
         */
        gbp_endpoint_group gepg(fwd.vnid, *encap_link, rd, bd);
        OM::write(epg_uuid, gepg);

        /*
         * Add the encap-link to the BD
         *
         * If the encap link is a VLAN, then set the pop VTR operation on the
         * link so that the VLAN tag is correctly pop/pushed on rx/tx resp.
         */
        l2_binding l2_upl(*encap_link, bd);
        if (interface::type_t::VXLAN != encap_link->type())
        {
            l2_upl.set(l2_binding::l2_vtr_op_t::L2_VTR_POP_1, fwd.vnid);
        }
        OM::write(epg_uuid, l2_upl);

        /*
         * Create a BVI interface for the EPG and add it to the bridge-domain
         */
        interface bvi("bvi-" + std::to_string(bd.id()), interface::type_t::BVI,
                      interface::admin_state_t::UP, rd);
        if (m_vr)
        {
            /*
             * Set the BVI's MAC address to the Virtual Router
             * address, so packets destined to the VR are handled
             * by layer 3.
             */
            bvi.set(m_vr->mac());
        }
        OM::write(epg_uuid, bvi);

        /*
         * The BVI is the NAT inside interface for the VMs
         */
        nat_binding nb6(bvi, direction_t::INPUT, l3_proto_t::IPV6,
                        nat_binding::zone_t::INSIDE);
        nat_binding nb4(bvi, direction_t::INPUT, l3_proto_t::IPV4,
                        nat_binding::zone_t::INSIDE);
        OM::write(epg_uuid, nb4);
        OM::write(epg_uuid, nb6);

        /*
         * Add the BVIs to the BD
         */
        l2_binding l2_bvi(bvi, bd);
        OM::write(epg_uuid, l2_bvi);

        /*
         * the bridge is not in learning mode. So add an L2FIB entry for the BVI
         */
        bridge_domain_entry be(bd, bvi.l2_address().to_mac(), bvi);
        OM::write(epg_uuid, be);

        /*
         * For each subnet the EPG has
         */
        opflexagent::PolicyManager::subnet_vector_t subnets;
        m_agent.getPolicyManager().getSubnetsForGroup(epgURI, subnets);

        for (auto sn : subnets)
        {
            boost::optional<boost::asio::ip::address> routerIp =
                opflexagent::PolicyManager::getRouterIpForSubnet(*sn);

            if (!sn->getPrefixLen() || !sn->getAddress()) continue;

            if (routerIp)
            {
                boost::asio::ip::address raddr = routerIp.get();
                /*
                 * - apply the host prefix on the BVI
                 * - add an entry into the ARP Table for it.
                 */
                l3_binding l3(bvi, {raddr});
                OM::write(epg_uuid, l3);

                bridge_domain_arp_entry bae(bd, raddr,
                                            bvi.l2_address().to_mac());
                OM::write(epg_uuid, bae);
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
    catch (EndPointGroupManager::NoFowardInfo &nofwd)
    {
        OLOGD << "NOT Updating endpoint-group:" << epgURI;
    }
}

}; // namespace VPP

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */
