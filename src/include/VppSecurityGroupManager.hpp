/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __VPP_SECURITY_GROUP_MANAGER_H__
#define __VPP_SECURITY_GROUP_MANAGER_H__

#include <opflexagent/Agent.h>
#include <opflexagent/EndpointManager.h>

#include <vom/acl_ethertype.hpp>
#include <vom/acl_list.hpp>

using namespace VOM;

namespace VPP
{
class SecurityGroupManager
{
  public:
    static void
    build_update(opflexagent::Agent &agent,
                 const opflexagent::EndpointListener::uri_set_t &secGrps,
                 const std::string &secGrpId, ACL::l3_list::rules_t &in_rules,
                 ACL::l3_list::rules_t &out_rules,
                 ACL::acl_ethertype::ethertype_rules_t &ethertype_rules);

    static std::string
    get_id(const opflexagent::EndpointListener::uri_set_t &secGrps);
};
}; // namespace VPP

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */

#endif
