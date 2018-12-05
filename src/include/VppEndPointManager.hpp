/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2017-2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __VPP_END_POINT_H__
#define __VPP_END_POINT_H__

#include <string>

#include "opflexagent/Agent.h"
#include "opflexagent/EndpointManager.h"

#include <vom/interface.hpp>
#include <vom/interface_cmds.hpp>

#include "VppIdGen.hpp"
#include "VppUplink.h"
#include "VppVirtualRouter.h"

namespace VOM
{
class bridge_domain;
class route_domain;
};

namespace VPP
{
class EndPointManager : public VOM::interface::stat_listener
{
  public:
    EndPointManager(opflexagent::Agent &agent, IdGen &id_gen, Uplink &uplink,
                    std::shared_ptr<VirtualRouter> vr);

    void handle_update(const std::string &uuid);

    static std::string
    getSecGrpSetId(const opflexagent::EndpointListener::uri_set_t &secGrps);

  private:
    struct NoEpInterface
    {
    };

    /**
     * Event listener override to get Interface stats
     */
    void handle_interface_stat(VOM::interface_cmds::stats_enable_cmd *e);
    void handle_interface_stat_i(VOM::interface_cmds::stats_enable_cmd *e);

    static std::shared_ptr<interface>
    mk_bd_interface(const opflexagent::Endpoint &ep, const bridge_domain &bd,
                    const route_domain &rd) throw(NoEpInterface);

    /**
     * Referene to the uber-agent
     */
    opflexagent::Agent &m_agent;

    IdGen &m_id_gen;
    Uplink &m_uplink;
    std::shared_ptr<VirtualRouter> m_vr;
};

}; // namespace VPP

#endif
