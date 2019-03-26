/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <boost/optional.hpp>

#include <opflexagent/PolicyManager.h>

#include <modelgbp/gbp/ExternalInterface.hpp>
#include <modelgbp/gbp/L3ExternalDomain.hpp>
#include <modelgbp/gbp/Subnet.hpp>

#include <vom/gbp_subnet.hpp>
#include <vom/gbp_ext_itf.hpp>
#include <vom/l3_binding.hpp>
#include <vom/route.hpp>

#include "VppLog.hpp"
#include "VppUtil.hpp"
#include "VppExtItfManager.hpp"
#include "VppEndPointGroupManager.hpp"
#include "VppRouteManager.hpp"

using namespace VOM;

namespace VPP
{
ExtItfManager::ExtItfManager(Runtime &runtime)
    : m_runtime(runtime)
{
}

void
ExtItfManager::handle_update(const opflex::modb::URI &uri)
{
    OM::mark_n_sweep ms(uri.toString());
    const std::string &uuid = uri.toString();

    boost::optional<std::shared_ptr<modelgbp::gbp::ExternalInterface> > ext_itf =
        modelgbp::gbp::ExternalInterface::resolve(m_runtime.agent.getFramework(), uri);

    if (!ext_itf)
    {
        VLOGD << "External-Interface; delete: " << uri;
        return;
    }
    VLOGD << "External-Interface; update: " << uri;

    boost::optional<std::shared_ptr<modelgbp::gbp::ExternalL3BridgeDomain>> op_bd = 
      m_runtime.policy_manager().getBDForExternalInterface(uri);

    if (!op_bd)
    {
        VLOGE << "External-Interface; no ExternalBridgeDomain: " << uri;
        return;
    }

    boost::optional<std::shared_ptr<modelgbp::gbp::RoutingDomain>> op_rd =
      m_runtime.policy_manager().getRDForExternalInterface(uri);

    if (!op_rd)
    {
        VLOGE << "External-Interface; no RouteDomain: " << uri;
        return;
    }

    uint32_t rd_id =
      m_runtime.id_gen.get(modelgbp::gbp::RoutingDomain::CLASS_ID,
                                          op_rd.get()->getURI());

    route_domain rd(rd_id);
    OM::write(uuid, rd);

    uint32_t bd_id = m_runtime.id_gen.get(modelgbp::gbp::BridgeDomain::CLASS_ID,
                                          op_bd.get()->getURI());

    bridge_domain bd(bd_id, bridge_domain::learning_mode_t::OFF);
    OM::write(uuid, bd);

    /*
     * Create a BVI interface for the EPG and add it to the bridge-domain
     */
    std::shared_ptr<interface> bvi =
      EndPointGroupManager::mk_bvi(m_runtime, uuid, bd, rd,
                                   mac_from_modb(ext_itf.get()->getMac()));

    /*
     * Add the mcast tunnels for flooding
     */
    boost::optional<std::string> maddr =
      m_runtime.policy_manager().getBDMulticastIPForExternalInterface(uri);
    boost::optional<uint32_t> bd_vnid =
      m_runtime.policy_manager().getBDVnidForExternalInterface(uri);

    if (!(bd_vnid && maddr))
    {
      VLOGE << "External-Interface; no VNI/mcast-address: " << uri;
      return;
    }

    std::shared_ptr<vxlan_tunnel> vt_mc =
      EndPointGroupManager::mk_mcast_tunnel(m_runtime, uuid,
                                            bd_vnid.get(), maddr.get());

    /*
     * there's no leanring of EPs in an external BD
     */
    gbp_bridge_domain gbd(bd, *bvi, {}, vt_mc,
                          gbp_bridge_domain::flags_t::DO_NOT_LEARN);
    OM::write(uuid, gbd);
    gbp_route_domain grd(rd);
    OM::write(uuid, grd);

    /*
     * the encap on the external-interface is a vlan ID
     */
    boost::optional<uint32_t> vlan_id = ext_itf.get()->getEncap();

    if (vlan_id)
      ;

    /*
     * Add the /32 to the BVI
     */
    boost::optional<const std::string&> s_addr = ext_itf.get()->getAddress();

    if (!s_addr)
    {
        VLOGI << "External-Interface; no prefix: " << uri;
        return;
    }
    boost::asio::ip::address p_addr =
	boost::asio::ip::address::from_string(s_addr.get());

    l3_binding l3b(*bvi, {p_addr});
    OM::write(uuid, l3b);

    opflexagent::PolicyManager::subnet_vector_t subnets;

    m_runtime.policy_manager().getSubnetsForExternalInterface(uri, subnets);

    for (auto sn : subnets)
    {
	if (!sn->getPrefixLen() || !sn->getAddress()) continue;

	route::prefix_t pfx(sn->getAddress().get(),
			    sn->getPrefixLen().get());

	route::ip_route ipr(rd, pfx, {route::path::special_t::DROP});
	OM::write(uuid, ipr);
    }

    /*
     * This BVI is the ExternalInterface
     */
    gbp_ext_itf gei(*bvi, gbd, grd);
    OM::write(uuid, gei);

    /*
     * Add any external networks
     */
    boost::optional<std::shared_ptr<modelgbp::gbp::L3ExternalDomain>> ext_dom =
        m_runtime.policy_manager().getExternalDomainForExternalInterface(uri);

    if (!ext_dom)
    {
        VLOGI << "External-Interface; no ExternalDomain: " << uri;
        return;
    }

    RouteManager::mk_ext_nets(m_runtime, rd, uri, ext_dom.get());
}

}; // namepsace VPP

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */
