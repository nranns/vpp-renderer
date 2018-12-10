/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __VPP_ROUTE_DOMAIN_MANAGER_H__
#define __VPP_ROUTE_DOMAIN_MANAGER_H__

#include <opflexagent/Agent.h>

#include "VppIdGen.hpp"
#include "VppUplink.hpp"

namespace VPP
{
class RouteDomainManager
{
  public:
    RouteDomainManager(opflexagent::Agent &agent,
                       IdGen &id_gen,
                       Uplink &uplink);

    void handle_update(const opflex::modb::URI &uri);

  private:
    /**
     * Referene to the uber-agent
     */
    opflexagent::Agent &m_agent;
    IdGen &m_id_gen;
    Uplink &m_uplink;
};
}; // namespace VPP

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */

#endif
