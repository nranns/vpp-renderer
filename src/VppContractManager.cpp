/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <opflexagent/PolicyManager.h>

#include <modelgbp/gbp/HashingAlgorithmEnumT.hpp>
#include <modelgbp/gbp/RoutingDomain.hpp>

#include <modelgbp/gbp/ConnTrackEnumT.hpp>
#include <modelgbp/gbp/DirectionEnumT.hpp>
#include <modelgbp/l2/EtherTypeEnumT.hpp>

#include <vom/acl_ethertype.hpp>
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

static uint32_t
getRdId(IdGen &id_gen,
        const std::shared_ptr<modelgbp::gbp::RoutingDomain> epgRd)
{
    uint32_t rdId = 0;
    if (epgRd)
    {
        boost::optional<opflex::modb::URI> rdURI = epgRd.get()->getURI();
        if (rdURI)
            rdId =
                id_gen.get(modelgbp::gbp::RoutingDomain::CLASS_ID, rdURI.get());
    }
    return rdId;
}

static uint32_t
getBdId(IdGen &id_gen, const std::shared_ptr<modelgbp::gbp::BridgeDomain> epgBd)
{
    uint32_t bdId = 0;
    if (epgBd)
    {
        boost::optional<opflex::modb::URI> bdURI = epgBd.get()->getURI();
        bdId = id_gen.get(modelgbp::gbp::BridgeDomain::CLASS_ID, bdURI.get());
    }
    return bdId;
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

    gbp_contract::gbp_rules_t gbp_rules;
    ACL::l3_list::rules_t in_rules, out_rules;
    gbp_contract::ethertype_set_t in_ethertypes, out_ethertypes;

    for (auto rule : rules)
    {
        uint8_t dir = rule->getDirection();
        const std::shared_ptr<modelgbp::gbpe::L24Classifier> &cls =
            rule->getL24Classifier();
        uint32_t priority = rule->getPriority();
        const ethertype_t &etherType = ethertype_t::from_numeric_val(
            cls->getEtherT(modelgbp::l2::EtherTypeEnumT::CONST_UNSPECIFIED));
        ACL::action_t act = ACL::action_t::from_bool(
            rule->getAllow(),
            cls->getConnectionTracking(
                modelgbp::gbp::ConnTrackEnumT::CONST_NORMAL));

        if (dir == modelgbp::gbp::DirectionEnumT::CONST_BIDIRECTIONAL ||
            dir == modelgbp::gbp::DirectionEnumT::CONST_IN)
        {
            auto it = out_ethertypes.find(etherType);
            if (it == out_ethertypes.end()) out_ethertypes.insert(etherType);
        }
        if (dir == modelgbp::gbp::DirectionEnumT::CONST_BIDIRECTIONAL ||
            dir == modelgbp::gbp::DirectionEnumT::CONST_OUT)
        {
            auto it = in_ethertypes.find(etherType);
            if (it == in_ethertypes.end()) in_ethertypes.insert(etherType);
        }

        if (etherType != modelgbp::l2::EtherTypeEnumT::CONST_IPV4 &&
            etherType != modelgbp::l2::EtherTypeEnumT::CONST_IPV6)
        {
            VLOGD << "Contract for Protocol " << etherType.to_string()
                  << " ,(IPv4/IPv6)"
                  << " are allowed";
            continue;
        }

        route::prefix_t srcIp(route::prefix_t::ZERO);
        route::prefix_t dstIp(route::prefix_t::ZERO);

        if (etherType == modelgbp::l2::EtherTypeEnumT::CONST_IPV6)
        {
            srcIp = route::prefix_t::ZEROv6;
            dstIp = route::prefix_t::ZEROv6;
        }

        ACL::l3_rule l3_rule(priority, act, srcIp, dstIp);
        setParamUpdate(*cls, l3_rule);
        if (dir == modelgbp::gbp::DirectionEnumT::CONST_BIDIRECTIONAL ||
            dir == modelgbp::gbp::DirectionEnumT::CONST_IN)
        {
            out_rules.insert(l3_rule);
        }
        if (dir == modelgbp::gbp::DirectionEnumT::CONST_BIDIRECTIONAL ||
            dir == modelgbp::gbp::DirectionEnumT::CONST_OUT)
        {
            in_rules.insert(l3_rule);
        }

        if (rule->getRedirect())
        {
            opflexagent::PolicyManager::redir_dest_list_t redirList;
            gbp_rule::next_hops_t nhs;
            uint8_t hashAlgo = 0, resilientHashEnabled = 0;
            boost::optional<opflex::modb::URI> destGrpUri =
                rule->getRedirectDestGrpURI();
            polMgr.getPolicyDestGroup(
                destGrpUri.get(), redirList, hashAlgo, resilientHashEnabled);

            for (auto dst : redirList)
            {
                uint8_t macAddr[6] = {0};
                dst->getMac().toUIntArray(macAddr);
                mac_address_t mac(macAddr);
                gbp_rule::next_hop_t nh(dst->getIp(),
                                        mac,
                                        getBdId(m_id_gen, dst->getBD()),
                                        getRdId(m_id_gen, dst->getRD()));
                nhs.insert(nh);
            }

            if (hashAlgo ==
                modelgbp::gbp::HashingAlgorithmEnumT::CONST_SYMMETRIC)
            {
                gbp_rule::next_hop_set_t next_hop_set(
                    gbp_rule::hash_mode_t::SYMMETRIC, nhs);
                gbp_rule gr(rule->getPriority(),
                            next_hop_set,
                            gbp_rule::action_t::REDIRECT);
                gbp_rules.insert(gr);
            }
            else if (hashAlgo ==
                     modelgbp::gbp::HashingAlgorithmEnumT::CONST_DSTIP)
            {
                gbp_rule::next_hop_set_t next_hop_set(
                    gbp_rule::hash_mode_t::DST_IP, nhs);
                gbp_rule gr(rule->getPriority(),
                            next_hop_set,
                            gbp_rule::action_t::REDIRECT);
                gbp_rules.insert(gr);
            }
            else if (hashAlgo ==
                     modelgbp::gbp::HashingAlgorithmEnumT::CONST_SRCIP)
            {
                gbp_rule::next_hop_set_t next_hop_set(
                    gbp_rule::hash_mode_t::SRC_IP, nhs);
                gbp_rule gr(rule->getPriority(),
                            next_hop_set,
                            gbp_rule::action_t::REDIRECT);
                gbp_rules.insert(gr);
            }
        }
        else if (act == ACL::action_t::PERMIT ||
                 act == ACL::action_t::PERMITANDREFLEX)
        {
            gbp_rule gr(rule->getPriority(), gbp_rule::action_t::PERMIT);
            gbp_rules.insert(gr);
        }
        else
        {
            gbp_rule gr(rule->getPriority(), gbp_rule::action_t::DENY);
            gbp_rules.insert(gr);
        }
    }

    for (const uint32_t &pvnid : provIds)
    {
        for (const uint32_t &cvnid : consIds)
        {
            if (pvnid == cvnid) /* intra group is allowed by default */
                continue;

            VLOGD << "Contract prov:" << pvnid << " cons:" << cvnid;

            if (!in_rules.empty())
            {
                ACL::l3_list inAcl(uuid + "in", in_rules);
                OM::write(uuid, inAcl);

                gbp_contract gbpc_in(
                    pvnid, cvnid, inAcl, gbp_rules, in_ethertypes);
                OM::write(uuid, gbpc_in);
            }
            if (!out_rules.empty())
            {
                ACL::l3_list outAcl(uuid + "out", out_rules);
                OM::write(uuid, outAcl);

                gbp_contract gbpc_out(
                    cvnid, pvnid, outAcl, gbp_rules, out_ethertypes);
                OM::write(uuid, gbpc_out);
            }
        }
    }
}

}; // namespace VPP

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */
