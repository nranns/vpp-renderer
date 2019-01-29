/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __VPP_RUNTIME_H__
#define __VPP_RUNTIME_H__

#include <opflexagent/Agent.h>

#include "VppIdGen.hpp"
#include "VppUplink.hpp"
#include "VppVirtualRouter.hpp"

namespace VPP
{
struct Runtime
{
    Runtime(opflexagent::Agent &agent_, opflexagent::IdGenerator &idGen)
        : agent(agent_)
        , id_gen(idGen)
        , uplink(agent)
    {
    }

    opflexagent::PolicyManager &policy_manager()
    {
        return agent.getPolicyManager();
    }

    /**
     * Referene to the uber-agent
     */
    opflexagent::Agent &agent;
    /**
     * ID generator instance
     */
    IdGen id_gen;
    /**
     * Uplink interface manager
     */
    Uplink uplink;
    /**
     * Virtual Router Settings
     */
    std::shared_ptr<VirtualRouter> vr;

  private:
    Runtime(const Runtime &);
};
}; // namespace VPP

#endif
