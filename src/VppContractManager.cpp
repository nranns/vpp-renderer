/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <opflexagent/PolicyManager.h>

#include <modelgbp/gbp/RoutingDomain.hpp>

#include <vom/acl_list.hpp>
#include <vom/gbp_contract.hpp>
#include <vom/om.hpp>

#include "VppContractManager.hpp"
#include "VppLog.hpp"

using namespace VOM;

namespace VPP
{
ContractManager::ContractManager(opflexagent::Agent &agent, IdGen &id_gen)
    : m_agent(agent)
    , m_id_gen(id_gen)
{
}

/**
 * Get the VNID for the specified endpoint groups or L3 external
 * networks
 *
 * @param uris URIs of endpoint groups to search for
 * @param ids the corresponding set of vnids
 */
static uint32_t
get_ext_net_vnid(IdGen &id_gen, const opflex::modb::URI &uri)
{
    // External networks are assigned private VNIDs that have bit 31 (MSB)
    // set to 1. This is fine because legal VNIDs are 24-bits or less.
    return (id_gen.get(modelgbp::gbp::L3ExternalNetwork::CLASS_ID, uri) |
            (1 << 31));
}

static void
get_group_vnid(opflexagent::Agent &agent,
               IdGen &id_gen,
               const std::unordered_set<opflex::modb::URI> &uris,
               std::unordered_set<uint32_t> &ids)
{
    opflexagent::PolicyManager &pm = agent.getPolicyManager();
    for (auto &u : uris)
    {
        boost::optional<uint32_t> vnid = pm.getVnidForGroup(u);
        boost::optional<std::shared_ptr<modelgbp::gbp::RoutingDomain>> rd;
        if (vnid)
        {
            rd = pm.getRDForGroup(u);
        }
        else
        {
            rd = pm.getRDForL3ExtNet(u);
            if (rd)
            {
                vnid = get_ext_net_vnid(id_gen, u);
            }
        }
        if (vnid && rd)
        {
            ids.insert(vnid.get());
        }
    }
}

void
ContractManager::handle_update(const opflex::modb::URI &uri)
{
    VLOGD << "Updating contract " << uri;

    const std::string &uuid = uri.toString();

    OM::mark_n_sweep ms(uuid);

    opflexagent::PolicyManager &polMgr = m_agent.getPolicyManager();
    if (!polMgr.contractExists(uri))
    {
        // Contract removed
        return;
    }

    opflexagent::PolicyManager::uri_set_t provURIs;
    opflexagent::PolicyManager::uri_set_t consURIs;
    opflexagent::PolicyManager::uri_set_t intraURIs;
    polMgr.getContractProviders(uri, provURIs);
    polMgr.getContractConsumers(uri, consURIs);
    polMgr.getContractIntra(uri, intraURIs);

    typedef std::unordered_set<uint32_t> id_set_t;
    id_set_t provIds;
    id_set_t consIds;
    id_set_t intraIds;
    get_group_vnid(m_agent, m_id_gen, provURIs, provIds);
    get_group_vnid(m_agent, m_id_gen, consURIs, consIds);

    opflexagent::PolicyManager::rule_list_t rules;
    polMgr.getContractRules(uri, rules);

    for (const uint32_t &pvnid : provIds)
    {
        for (const uint32_t &cvnid : consIds)
        {
            if (pvnid == cvnid) /* intra group is allowed by default */
                continue;

            VLOGD << "Contract prov:" << pvnid << " cons:" << cvnid;

            /*
             * At this point we are implementing only the neutron virtual
             * router concept. So we use a permit any-any rule and rely
             * only on the GDBP EPG restructions
             */
            ACL::l3_rule rule(0,
                              ACL::action_t::PERMIT,
                              route::prefix_t::ZERO,
                              route::prefix_t::ZERO);

            ACL::l3_list acl(uuid, {rule});
            OM::write(uuid, acl);

            gbp_contract gbpc(pvnid, cvnid, acl);
            OM::write(uuid, gbpc);
        }
    }
}

}; // namepsace VPP

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */
