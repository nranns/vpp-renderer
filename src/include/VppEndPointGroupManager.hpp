/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <boost/optional.hpp>

#include <opflexagent/Agent.h>

#include "VppIdGen.hpp"
#include "VppUplink.h"
#include "VppVirtualRouter.h"

namespace VPP
{
class EndPointGroupManager
{
  public:
    struct ForwardInfo
    {
        uint32_t vnid;
        uint32_t rdId;
        uint32_t bdId;
        boost::optional<opflex::modb::URI> rdURI;
        boost::optional<opflex::modb::URI> bdURI;
    };
    struct NoFowardInfo
    {
    };

    EndPointGroupManager(opflexagent::Agent &agent, IdGen &id_gen,
                         Uplink &uplink, std::shared_ptr<VirtualRouter> vr);

    static ForwardInfo
    get_fwd_info(opflexagent::Agent &agent, IdGen &id_gen,
                 const opflex::modb::URI &uri) throw(NoFowardInfo);

    void handle_update(const opflex::modb::URI &epgURI);

  private:
    /**
     * Referene to the uber-agent
     */
    opflexagent::Agent &m_agent;

    IdGen &m_id_gen;
    Uplink &m_uplink;
    std::shared_ptr<VirtualRouter> m_vr;
};
};

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */
