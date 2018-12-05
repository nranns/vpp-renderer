/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2017-2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <string>

#include "opflexagent/Agent.h"

#include <vom/interface_cmds.hpp>

#include "VppIdGen.hpp"
#include "VppUplink.hpp"
#include "VppVirtualRouter.hpp"

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
    struct NoEpInterfaceException
    {
    };

    EndPointManager(opflexagent::Agent &agent,
                    IdGen &id_gen,
                    Uplink &uplink,
                    std::shared_ptr<VirtualRouter> vr);
    virtual ~EndPointManager();

    void handle_update(const std::string &uuid);

    static std::string get_ep_interface_name(
        const opflexagent::Endpoint &ep) throw(NoEpInterfaceException);

  private:
    /**
     * Event listener override to get Interface stats
     */
    void handle_interface_stat_i(VOM::interface_cmds::stats_enable_cmd *e);
    virtual void
    handle_interface_stat(VOM::interface_cmds::stats_enable_cmd *e);

    static std::shared_ptr<interface>
    mk_bd_interface(const opflexagent::Endpoint &ep,
                    const bridge_domain &bd,
                    const route_domain &rd) throw(NoEpInterfaceException);

    /**
     * Referene to the uber-agent
     */
    opflexagent::Agent &m_agent;

    IdGen &m_id_gen;
    Uplink &m_uplink;
    std::shared_ptr<VirtualRouter> m_vr;
};

}; // namespace VPP
