/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __VPP_ROUTE_MANAGER_H__
#define __VPP_ROUTE_MANAGER_H__

#include <opflexagent/Agent.h>

#include "VppRuntime.hpp"

namespace VPP
{
class RouteManager
{
  public:
    RouteManager(Runtime &runtime);

    void handle_domain_update(const opflex::modb::URI &uri);
    void handle_static_update(const opflex::modb::URI &uri);
    void handle_remote_update(const opflex::modb::URI &uri);

  private:
    /**
     * Reference to the runtime data
     */
    Runtime &m_runtime;
};
}; // namespace VPP

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */

#endif
