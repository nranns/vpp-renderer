/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <opflexagent/PolicyManager.h>
#include <opflexagent/logging.h>

#include <modelgbp/gbp/ConnTrackEnumT.hpp>
#include <modelgbp/gbp/DirectionEnumT.hpp>
#include <modelgbp/l2/EtherTypeEnumT.hpp>
#include <modelgbp/l4/TcpFlagsEnumT.hpp>

#include <vom/acl_binding.hpp>

#include "VppEndPointManager.hpp"
#include "VppLog.hpp"
#include "VppSecurityGroupManager.hpp"

namespace VPP
{
SecurityGroupManager::SecurityGroupManager(opflexagent::Agent &agent)
    : m_agent(agent)
{
}

void
setParamUpdate(modelgbp::gbpe::L24Classifier &cls, ACL::l3_rule &rule)
{
    using modelgbp::l4::TcpFlagsEnumT;

    if (cls.isArpOpcSet())
    {
        rule.set_proto(cls.getArpOpc().get());
    }

    if (cls.isProtSet())
    {
        rule.set_proto(cls.getProt(0));
    }

    if (cls.isSFromPortSet())
    {
        rule.set_src_from_port(cls.getSFromPort(0));
    }
    else if (cls.isIcmpTypeSet())
    {
        rule.set_src_from_port(cls.getIcmpType(0));
    }

    if (cls.isSToPortSet())
    {
        rule.set_src_to_port(cls.getSToPort(0));
    }
    else if (cls.isIcmpTypeSet())
    {
        rule.set_src_to_port(cls.getIcmpType(0));
    }

    if (cls.isDFromPortSet())
    {
        rule.set_dst_from_port(cls.getDFromPort(0));
    }
    else if (cls.isIcmpCodeSet())
    {
        rule.set_dst_from_port(cls.getIcmpCode(0));
    }

    if (cls.isDToPortSet())
    {
        rule.set_dst_to_port(cls.getDToPort(0));
    }
    else if (cls.isIcmpCodeSet())
    {
        rule.set_dst_to_port(cls.getIcmpCode(0));
    }

    if (6 == cls.getProt(0) && cls.isTcpFlagsSet())
    {
        rule.set_tcp_flags_mask(
            cls.getTcpFlags(TcpFlagsEnumT::CONST_UNSPECIFIED));
        rule.set_tcp_flags_value(
            cls.getTcpFlags(TcpFlagsEnumT::CONST_UNSPECIFIED));
    }

    if (6 == cls.getProt(0) || 17 == cls.getProt(0))
    {
        if (rule.srcport_or_icmptype_last() == 0) rule.set_src_to_port(65535);
        if (rule.dstport_or_icmpcode_last() == 0) rule.set_dst_to_port(65535);
    }

    if (1 == cls.getProt(0) || 58 == cls.getProt(0))
    {
        if (rule.srcport_or_icmptype_last() == 0) rule.set_src_to_port(255);
        if (rule.dstport_or_icmpcode_last() == 0) rule.set_dst_to_port(255);
    }
}

void
SecurityGroupManager::build_update(
    opflexagent::Agent &agent,
    const opflexagent::EndpointListener::uri_set_t &secGrps,
    const std::string &secGrpId,
    ACL::l3_list::rules_t &in_rules,
    ACL::l3_list::rules_t &out_rules,
    ACL::acl_ethertype::ethertype_rules_t &ethertype_rules)
{
    if (secGrps.empty())
    {
        // OM::remove(secGrpId);
        return;
    }

    VLOGD << "building security group update";

    for (const opflex::modb::URI &secGrp : secGrps)
    {
        opflexagent::PolicyManager::rule_list_t rules;
        agent.getPolicyManager().getSecGroupRules(secGrp, rules);

        for (auto pc : rules)
        {
            uint8_t dir = pc->getDirection();
            const std::shared_ptr<modelgbp::gbpe::L24Classifier> &cls =
                pc->getL24Classifier();
            uint32_t priority = pc->getPriority();
            const ethertype_t &etherType =
                ethertype_t::from_numeric_val(cls->getEtherT(
                    modelgbp::l2::EtherTypeEnumT::CONST_UNSPECIFIED));
            ACL::action_t act = ACL::action_t::from_bool(
                pc->getAllow(),
                cls->getConnectionTracking(
                    modelgbp::gbp::ConnTrackEnumT::CONST_NORMAL));

            if (dir == modelgbp::gbp::DirectionEnumT::CONST_BIDIRECTIONAL ||
                dir == modelgbp::gbp::DirectionEnumT::CONST_IN)
            {
                ACL::ethertype_rule_t et(etherType, direction_t::OUTPUT);
                ethertype_rules.insert(et);
            }
            if (dir == modelgbp::gbp::DirectionEnumT::CONST_BIDIRECTIONAL ||
                dir == modelgbp::gbp::DirectionEnumT::CONST_OUT)
            {
                ACL::ethertype_rule_t et(etherType, direction_t::INPUT);
                ethertype_rules.insert(et);
            }

            if (etherType != modelgbp::l2::EtherTypeEnumT::CONST_IPV4 &&
                etherType != modelgbp::l2::EtherTypeEnumT::CONST_IPV6)
            {
                VLOGW << "Security Group Rule for Protocol "
                      << etherType.to_string() << " ,(IPv4/IPv6) Security"
                      << "Rules are allowed";
                continue;
            }

            if (!pc->getRemoteSubnets().empty())
            {
                boost::optional<const opflexagent::network::subnets_t &>
                    remoteSubs;
                remoteSubs = pc->getRemoteSubnets();
                for (const opflexagent::network::subnet_t &sub :
                     remoteSubs.get())
                {
                    bool is_v6 =
                        boost::asio::ip::address::from_string(sub.first)
                            .is_v6();

                    if ((etherType ==
                             modelgbp::l2::EtherTypeEnumT::CONST_IPV4 &&
                         is_v6) ||
                        (etherType ==
                             modelgbp::l2::EtherTypeEnumT::CONST_IPV6 &&
                         !is_v6))
                        continue;

                    route::prefix_t ip(sub.first, sub.second);
                    route::prefix_t ip2(route::prefix_t::ZERO);

                    if (etherType == modelgbp::l2::EtherTypeEnumT::CONST_IPV6)
                    {
                        ip2 = route::prefix_t::ZEROv6;
                    }

                    if (dir == modelgbp::gbp::DirectionEnumT::
                                   CONST_BIDIRECTIONAL ||
                        dir == modelgbp::gbp::DirectionEnumT::CONST_IN)
                    {
                        ACL::l3_rule rule(priority, act, ip, ip2);
                        setParamUpdate(*cls, rule);
                        out_rules.insert(rule);
                    }
                    if (dir == modelgbp::gbp::DirectionEnumT::
                                   CONST_BIDIRECTIONAL ||
                        dir == modelgbp::gbp::DirectionEnumT::CONST_OUT)
                    {
                        ACL::l3_rule rule(priority, act, ip2, ip);
                        setParamUpdate(*cls, rule);
                        in_rules.insert(rule);
                    }
                }
            }
            else
            {
                route::prefix_t srcIp(route::prefix_t::ZERO);
                route::prefix_t dstIp(route::prefix_t::ZERO);

                if (etherType == modelgbp::l2::EtherTypeEnumT::CONST_IPV6)
                {
                    srcIp = route::prefix_t::ZEROv6;
                    dstIp = route::prefix_t::ZEROv6;
                }

                ACL::l3_rule rule(priority, act, srcIp, dstIp);
                setParamUpdate(*cls, rule);
                if (dir == modelgbp::gbp::DirectionEnumT::CONST_BIDIRECTIONAL ||
                    dir == modelgbp::gbp::DirectionEnumT::CONST_IN)
                {
                    out_rules.insert(rule);
                }
                if (dir == modelgbp::gbp::DirectionEnumT::CONST_BIDIRECTIONAL ||
                    dir == modelgbp::gbp::DirectionEnumT::CONST_OUT)
                {
                    in_rules.insert(rule);
                }
            }
        }
    }
}

std::string
SecurityGroupManager::get_id(
    const opflexagent::EndpointListener::uri_set_t &secGrps)
{
    std::stringstream ss;
    bool notfirst = false;
    for (auto &uri : secGrps)
    {
        if (notfirst) ss << ",";
        notfirst = true;
        ss << uri.toString();
    }
    return ss.str();
}

void
SecurityGroupManager::handle_set_update(
    const opflexagent::EndpointListener::uri_set_t &secGrps)
{
    VLOGD << "Updating security group set";

    ACL::l3_list::rules_t in_rules, out_rules;
    ACL::acl_ethertype::ethertype_rules_t ethertype_rules;
    const std::string secGrpId = get_id(secGrps);
    std::shared_ptr<ACL::l3_list> in_acl, out_acl;

    build_update(
        m_agent, secGrps, secGrpId, in_rules, out_rules, ethertype_rules);

    if (in_rules.empty() && out_rules.empty() && ethertype_rules.empty())
    {
        VLOGW << "in and out rules are empty";
        return;
    }

    opflexagent::EndpointManager &epMgr = m_agent.getEndpointManager();
    std::unordered_set<std::string> eps;
    epMgr.getEndpointsForSecGrps(secGrps, eps);

    for (const std::string &uuid : eps)
    {
        OM::mark_n_sweep ms(uuid);

        const opflexagent::Endpoint &endPoint = *epMgr.getEndpoint(uuid).get();
        const std::string vppInterfaceName =
            EndPointManager::get_ep_interface_name(endPoint);

        if (0 == vppInterfaceName.length()) continue;

        std::shared_ptr<interface> itf = interface::find(vppInterfaceName);

        if (!itf) continue;

        if (!ethertype_rules.empty())
        {
            ACL::acl_ethertype a_e(*itf, ethertype_rules);
            OM::write(uuid, a_e);
        }
        if (!in_rules.empty())
        {
            ACL::l3_list inAcl(secGrpId + "in", in_rules);
            OM::write(uuid, inAcl);

            ACL::l3_binding in_binding(direction_t::INPUT, *itf, inAcl);
            OM::write(uuid, in_binding);
        }
        if (!out_rules.empty())
        {
            ACL::l3_list outAcl(secGrpId + "out", out_rules);
            OM::write(uuid, outAcl);
            ACL::l3_binding out_binding(direction_t::OUTPUT, *itf, outAcl);
            OM::write(uuid, out_binding);
        }
    }
}

void
SecurityGroupManager::handle_update(const opflex::modb::URI &uri)
{
    std::unordered_set<opflexagent::EndpointListener::uri_set_t> secGrpSets;
    m_agent.getEndpointManager().getSecGrpSetsForSecGrp(uri, secGrpSets);
    for (auto &secGrpSet : secGrpSets)
        handle_set_update(secGrpSet);
}

}; // namepsace VPP
   /*
    * Local Variables:
    * eval: (c-set-style "llvm.org")
    * End:
    */
