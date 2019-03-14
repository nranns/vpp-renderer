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
#include <modelgbp/gbp/UnknownFloodModeEnumT.hpp>

#include <vom/bridge_domain.hpp>
#include <vom/bridge_domain_arp_entry.hpp>
#include <vom/bridge_domain_entry.hpp>
#include <vom/gbp_endpoint_group.hpp>
#include <vom/gbp_subnet.hpp>
#include <vom/gbp_vxlan.hpp>
#include <vom/igmp_binding.hpp>
#include <vom/igmp_listen.hpp>
#include <vom/l2_binding.hpp>
#include <vom/l3_binding.hpp>
#include <vom/nat_binding.hpp>
#include <vom/nat_static.hpp>
#include <vom/neighbour.hpp>
#include <vom/om.hpp>
#include <vom/route_domain.hpp>
#include <vom/vxlan_tunnel.hpp>

#include "VppEndPointGroupManager.hpp"
#include "VppLog.hpp"
#include "VppSpineProxy.hpp"

namespace VPP
{
EndPointGroupManager::EndPointGroupManager(Runtime &runtime)
    : m_runtime(runtime)
{
}

EndPointGroupManager::ForwardInfo::ForwardInfo()
    : vnid(0xfefefefe)
    , rdId(0xfefefefe)
    , bdId(0xfefefefe)
{
}

EndPointGroupManager::ForwardInfo
EndPointGroupManager::get_fwd_info_ext_itf(
    Runtime &runtime, const opflex::modb::URI &uri) throw(NoFowardInfoException)
{
    EndPointGroupManager::ForwardInfo fwd;
    opflexagent::PolicyManager &polMgr = runtime.policy_manager();

    fwd.vnid = 0xdeadbeaf;

    boost::optional<uint32_t> sclass = polMgr.getSclassForExternalInterface(uri);

    if (!sclass)
    {
        throw NoFowardInfoException("No Sclass for External-Interface");
    }
    fwd.sclass = sclass.get();

    boost::optional<std::shared_ptr<modelgbp::gbp::RoutingDomain>> epgRd =
        polMgr.getRDForExternalInterface(uri);
    boost::optional<std::shared_ptr<modelgbp::gbp::ExternalL3BridgeDomain>> epgBd =
        polMgr.getBDForExternalInterface(uri);


    if (epgRd)
    {
        fwd.rdURI = epgRd.get()->getURI();
        if (fwd.rdURI)
            fwd.rdId = runtime.id_gen.get(
                modelgbp::gbp::RoutingDomain::CLASS_ID, fwd.rdURI.get());
        else
          throw NoFowardInfoException("No RD-URI for External-Interface");
    }
    else
    {
      throw NoFowardInfoException("No RD for External-Interface");
    }

    if (epgBd)
    {
        fwd.bdURI = epgBd.get()->getURI();
        fwd.bdId = runtime.id_gen.get(modelgbp::gbp::BridgeDomain::CLASS_ID,
                                      fwd.bdURI.get());
    }
    else
    {
        throw NoFowardInfoException("No BD for EPG");
    }
    return fwd;

}

EndPointGroupManager::ForwardInfo
EndPointGroupManager::get_fwd_info(
    Runtime &runtime, const opflex::modb::URI &uri) throw(NoFowardInfoException)
{
    EndPointGroupManager::ForwardInfo fwd;
    opflexagent::PolicyManager &polMgr = runtime.policy_manager();
    boost::optional<uint32_t> epgVnid = polMgr.getVnidForGroup(uri);

    if (!epgVnid)
    {
        throw NoFowardInfoException("No EPG VNID");
    }
    fwd.vnid = epgVnid.get();

    boost::optional<uint32_t> sclass = polMgr.getSclassForGroup(uri);

    if (!sclass)
    {
        throw NoFowardInfoException("No EPG Sclass");
    }
    fwd.sclass = sclass.get();

    boost::optional<std::shared_ptr<modelgbp::gbp::RoutingDomain>> epgRd =
        polMgr.getRDForGroup(uri);
    boost::optional<std::shared_ptr<modelgbp::gbp::BridgeDomain>> epgBd =
        polMgr.getBDForGroup(uri);


    if (epgRd)
    {
        fwd.rdURI = epgRd.get()->getURI();
        if (fwd.rdURI)
            fwd.rdId = runtime.id_gen.get(
                modelgbp::gbp::RoutingDomain::CLASS_ID, fwd.rdURI.get());
        else
          throw NoFowardInfoException("No RD-URI for EPG");
    }
    else
    {
      throw NoFowardInfoException("No RD for EPG");
    }

    if (epgBd)
    {
        fwd.bdURI = epgBd.get()->getURI();
        fwd.bdId = runtime.id_gen.get(modelgbp::gbp::BridgeDomain::CLASS_ID,
                                      fwd.bdURI.get());
    }
    else
    {
        throw NoFowardInfoException("No BD for EPG");
    }
    return fwd;
}

std::shared_ptr<vxlan_tunnel>
EndPointGroupManager::mk_mcast_tunnel(Runtime &r,
                                      const std::string &key,
                                      uint32_t vni,
                                      const std::string &maddr)
{
  /*
   * Add the Vxlan mcast tunnel that will carry the broadcast
   * and multicast traffic
   */
  boost::asio::ip::address dst =
    boost::asio::ip::address::from_string(maddr);

  vxlan_tunnel vt(r.uplink.local_address(),
                  dst,
                  vni,
                  *r.uplink.local_interface(),
                  vxlan_tunnel::mode_t::GBP);
  OM::write(key, vt);

  /*
   * add the mcast group to accept via the uplink and
   * forward locally.
   */
  route::path via_uplink(*r.uplink.local_interface(),
                         nh_proto_t::IPV4);
  route::ip_mroute mroute({dst.to_v4(), 32});

  mroute.add(via_uplink, route::itf_flags_t::ACCEPT);
  mroute.add({route::path::special_t::LOCAL},
             route::itf_flags_t::FORWARD);
  OM::write(key, mroute);

  /*
   * join the group on the uplink interface
   */
  igmp_binding igmp_b(*r.uplink.local_interface());
  OM::write(key, igmp_b);

  igmp_listen igmp_l(igmp_b, dst.to_v4());
  OM::write(key, igmp_l);

  return (vt.singular());
}

std::shared_ptr<VOM::interface>
EndPointGroupManager::mk_bvi(Runtime &r,
                             const std::string &key,
                             const bridge_domain &bd,
                             const route_domain &rd,
                             const boost::optional<mac_address_t> &mac)
{
  std::shared_ptr<interface> bvi =
    std::make_shared<interface>("bvi-" + std::to_string(bd.id()),
                                interface::type_t::BVI,
                                interface::admin_state_t::UP,
                                rd);
  if (mac)
  {
    bvi->set(mac.get());
  }
  else if (r.vr)
  {
    /*
     * Set the BVI's MAC address to the Virtual Router
     * address, so packets destined to the VR are handled
     * by layer 3.
     */
    bvi->set(r.vr->mac());
  }
  OM::write(key, *bvi);

  /*
   * Add the BVI to the BD
   */
  l2_binding l2_bvi(*bvi, bd);
  OM::write(key, l2_bvi);

  /*
   * the bridge is not in learning mode. So add an L2FIB entry for the BVI
   */
  bridge_domain_entry be(bd, bvi->l2_address().to_mac(), *bvi);
  OM::write(key, be);

  return bvi;
}

std::shared_ptr<VOM::gbp_endpoint_group>
EndPointGroupManager::mk_group(Runtime &runtime,
                               const std::string &key,
                               const opflex::modb::URI &uri,
			       bool is_ext)
{
    std::shared_ptr<VOM::gbp_endpoint_group> gepg;

    try
    {
        /*
         * default retention policy of 2 minutes.
         */
        EndPointGroupManager::ForwardInfo fwd;
        gbp_endpoint_group::retention_t retention(120);

	if (is_ext)
	    fwd = get_fwd_info_ext_itf(runtime, uri);
	else
	    fwd = get_fwd_info(runtime, uri);

        boost::optional<std::shared_ptr<modelgbp::gbpe::EndpointRetention>> ret_pol =
            runtime.policy_manager().getL2EPRetentionPolicyForGroup(uri);

        if (ret_pol)
        {
            retention.remote_ep_timeout =
                ret_pol.get()->getRemoteEpAgingInterval(120);
        }

        /*
         * Construct the Bridge and routing Domains
         */
        bridge_domain bd(fwd.bdId, bridge_domain::learning_mode_t::OFF);
        OM::write(key, bd);
        route_domain rd(fwd.rdId);
        OM::write(key, rd);

        /*
         * Create a BVI interface for the EPG and add it to the bridge-domain
         */
        std::shared_ptr<interface> bvi = mk_bvi(runtime, key, bd, rd);

        std::shared_ptr<SpineProxy> spine_proxy = runtime.uplink.spine_proxy();

        if (spine_proxy)
        {
            /*
             * TRANSPORT mode
             * then a route domain that uses the v4 and v6 resp
             */
            boost::optional<uint32_t> rd_vnid;
            boost::optional<uint32_t> bd_vnid;
            boost::optional<std::string> bd_mcast;
	    if (is_ext)
	    {
		rd_vnid = runtime.policy_manager().getRDVnidForExternalInterface(uri);
		bd_vnid = runtime.policy_manager().getBDVnidForExternalInterface(uri);
		bd_mcast = runtime.policy_manager().getBDMulticastIPForExternalInterface(uri);
	    }
	    else
	    {
		rd_vnid = runtime.policy_manager().getRDVnidForGroup(uri);
		bd_vnid = runtime.policy_manager().getBDVnidForGroup(uri);
		bd_mcast = runtime.policy_manager().getBDMulticastIPForGroup(uri);
	    }

            if (bd_vnid && rd_vnid && bd_mcast)
            {
              std::shared_ptr<vxlan_tunnel> vt_mc, vt_v4, vt_v6, vt_mac;

              boost::optional<std::shared_ptr<modelgbp::gbp::FloodDomain>> flood_domain =
                runtime.policy_manager().getFDForGroup(uri);

              if (flood_domain)
                {
                  if (modelgbp::gbp::UnknownFloodModeEnumT::CONST_HWPROXY ==
                      flood_domain.get()->getUnknownFloodMode(0))
                    {
                      vt_v4 = spine_proxy->mk_v4(key, rd_vnid.get());
                      vt_v6 = spine_proxy->mk_v6(key, rd_vnid.get());
                      vt_mac = spine_proxy->mk_mac(key, bd_vnid.get());
                    }
                  else if (modelgbp::gbp::UnknownFloodModeEnumT::CONST_DROP ==
                           flood_domain.get()->getUnknownFloodMode(0))
                    {
                      // For Future Use
                      VLOGW << "UnknownFloodModeEnun=DROP will flood " << uri;
                    }
                }

              vt_mc = mk_mcast_tunnel(runtime, key, bd_vnid.get(), bd_mcast.get());
              l2_binding l2_vxbd(*vt_mc, bd);
              OM::write(key, l2_vxbd);

              gbp_route_domain grd(rd, vt_v4, vt_v6);
              OM::write(key, grd);

              gbp_vxlan gvx_rd(rd_vnid.get(), grd,
                               runtime.uplink.local_address().to_v4());
              OM::write(key, gvx_rd);

              /*
               * Add the base GBP-vxlan tunnels that will be used to derive
               * the learned endpoints
               */

              /*
               * construct a BD that uses the MAC spine proxy as the
               * UU-fwd interface
               */
              gbp_bridge_domain gbd(bd, bvi, vt_mac, vt_mc);
              OM::write(key, gbd);

              /*
               * base tunnel on which the TEPs derive and EPs are learnt
               */
              gbp_vxlan gvx_bd(bd_vnid.get(), gbd,
                               runtime.uplink.local_address().to_v4());
              OM::write(key, gvx_bd);

              gepg = std::make_shared<gbp_endpoint_group>(fwd.vnid, fwd.sclass, grd, gbd);
            }
            else
            {
              VLOGE << "no RD/BD vnid or sclass " << uri;
            }
        }
        else
        {
            /*
             * STITCHED MODE
             *
             * make the VLAN based uplink interface for the group
             */
            std::shared_ptr<interface> encap_link =
                runtime.uplink.mk_interface(key, fwd.vnid);

            /*
             * Add the encap-link to the BD
             *
             * If the encap link is a VLAN, then set the pop VTR operation on
             * the
             * link so that the VLAN tag is correctly pop/pushed on rx/tx resp.
             */
            l2_binding l2_upl(*encap_link, bd);
            if (interface::type_t::VXLAN != encap_link->type())
            {
              l2_upl.set(l2_vtr::option_t::POP_1, fwd.vnid);
            }
            OM::write(key, l2_upl);

            gbp_bridge_domain gbd(bd, *bvi);
            OM::write(key, gbd);

            gbp_route_domain grd(rd);
            OM::write(key, grd);

            gepg = std::make_shared<gbp_endpoint_group>(
                fwd.vnid, fwd.sclass, *encap_link, grd, gbd);
        }
        /*
         * GBP Endpoint Group
         */
        gepg->set(retention);
        OM::write(key, *gepg);
    }
    catch (EndPointGroupManager::NoFowardInfoException &nofwd)
    {
        VLOGD << "NOT Updating endpoint-group: "
              << nofwd.reason << " : " << uri;
    }

    return gepg;
}

void
EndPointGroupManager::handle_update(const opflex::modb::URI &epgURI)
{
    const std::string &epg_uuid = epgURI.toString();

    /*
     * Mark all of this EPG's state stale. this RAII pattern
     * will sweep all state that is not updated.
     */
    OM::mark_n_sweep ms(epg_uuid);

    VLOGD << "Updating endpoint-group:" << epgURI;

    opflexagent::PolicyManager &pm = m_runtime.policy_manager();

    if (!m_runtime.policy_manager().groupExists(epgURI))
    {
        VLOGD << "Deleting endpoint-group:" << epgURI;
        return;
    }

    std::shared_ptr<VOM::gbp_endpoint_group> gepg =
        mk_group(m_runtime, epg_uuid, epgURI);

    if (gepg)
    {
        std::shared_ptr<interface> bvi = gepg->get_bridge_domain()->get_bvi();
        std::shared_ptr<bridge_domain> bd =
            gepg->get_bridge_domain()->get_bridge_domain();
        std::shared_ptr<route_domain> rd =
            gepg->get_route_domain()->get_route_domain();

        /*
         * The BVI is the NAT inside interface for the VMs
         */
        nat_binding nb6(*bvi,
                        direction_t::INPUT,
                        l3_proto_t::IPV6,
                        nat_binding::zone_t::INSIDE);
        nat_binding nb4(*bvi,
                        direction_t::INPUT,
                        l3_proto_t::IPV4,
                        nat_binding::zone_t::INSIDE);
        OM::write(epg_uuid, nb4);
        OM::write(epg_uuid, nb6);

        /*
         * For each subnet the EPG has
         */
        opflexagent::PolicyManager::subnet_vector_t subnets;
        m_runtime.policy_manager().getSubnetsForGroup(epgURI, subnets);

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
                l3_binding l3(*bvi, {raddr});
                OM::write(epg_uuid, l3);

                bridge_domain_arp_entry bae(
                    *bd, raddr, bvi->l2_address().to_mac());
                OM::write(epg_uuid, bae);
            }
            /*
             * The subnet is an internal 'GBP subnet' i.e. it is one where
             * the egress the is the EPG's uplink. And the EPG is chosen
             * based on the packet's source port
             */
            route::prefix_t pfx(sn->getAddress().get(),
                                sn->getPrefixLen().get());

            gbp_subnet gs(*rd, pfx.low(),
                          (gepg->get_route_domain()->get_ip4_uu_fwd() ?
                           gbp_subnet::type_t::TRANSPORT :
                           gbp_subnet::type_t::STITCHED_INTERNAL));
            OM::write(epg_uuid, gs);
        }
    }
}

}; // namespace VPP

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */
