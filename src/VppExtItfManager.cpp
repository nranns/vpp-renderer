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

#include <vom/gbp_subnet.hpp>

#include "VppLog.hpp"
#include "VppExtItfManager.hpp"

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

    boost::optional<std::shared_ptr<modelgbp::gbp::L3ExternalDomain>> ext_dom =
        m_runtime.agent.getPolicyManager().getExternalDomainForExternalInterface(uri);

    if (!ext_dom)
    {
        VLOGE << "External-Interface; no ext-domain: " << uri;
        return;
    }

    boost::optional<std::shared_ptr<modelgbp::gbp::RoutingDomain>> op_rd =
        m_runtime.agent.getPolicyManager().getRDForExternalInterface(uri);

    if (!op_rd)
    {
        VLOGE << "External-Interface; no RouteDomain: " << uri;
    }

    uint32_t rd_id = m_runtime.id_gen.get(modelgbp::gbp::RoutingDomain::CLASS_ID,
                                          op_rd.get()->getURI());

    VOM::route_domain rd(rd_id);
    VOM::OM::write(uuid, rd);

    /* To get all the external networks in an external domain */
    std::vector<std::shared_ptr<modelgbp::gbp::L3ExternalNetwork>> ext_nets;
    ext_dom.get()->resolveGbpL3ExternalNetwork(ext_nets);

    for (std::shared_ptr<modelgbp::gbp::L3ExternalNetwork> net : ext_nets)
    {
        /* For each external network, get the sclass */
        boost::optional<uint32_t> sclass =
            m_runtime.agent.getPolicyManager().getSclassForExternalNet(uri);

        /* traverse each subnet in the network */
        std::vector<std::shared_ptr<modelgbp::gbp::ExternalSubnet> > ext_subs;
        net->resolveGbpExternalSubnet(ext_subs);

        for (std::shared_ptr<modelgbp::gbp::ExternalSubnet> snet : ext_subs)
        {
            if (!snet->isAddressSet() || !snet->isPrefixLenSet())
                    continue;

            VLOGD << "External-Interface; subnet:" << uri
                  << " external:" << ext_dom.get()->getName("n/a")
                  << " external-net:" << net->getName("n/a")
                  << " external-sub:" << snet->getAddress("n/a") << "/"
                  << std::to_string(snet->getPrefixLen(99));

            boost::asio::ip::address addr =
                boost::asio::ip::address::from_string(snet->getAddress().get());

            gbp_subnet gs(rd, {addr, snet->getPrefixLen().get()},
                          gbp_subnet::type_t::L3_OUT);
            OM::write(uuid, gs);
        }
    }
}

}; // namepsace VPP

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */
