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

#include "VppRuntime.hpp"

namespace VOM
{
class bridge_domain;
class route_domain;
class interface;
};

namespace VPP
{
class EndPointManager : public VOM::interface::stat_listener
{
  public:
    struct NoEpInterfaceException
    {
    };

    EndPointManager(Runtime &runtime);
    virtual ~EndPointManager();

    void handle_update(const std::string &uuid);
    void handle_external_update(const std::string &uuid);
    void handle_remote_update(const std::string &uuid);

    static std::string get_ep_interface_name(
        const opflexagent::Endpoint &ep) throw(NoEpInterfaceException);

    virtual void handle_interface_stat(const interface &);

  private:
    void handle_update_i(const std::string &uuid, bool is_external);

    /**
     * Event listener override to get Interface stats
     */
    void handle_interface_stat_i(const interface &);

    static std::shared_ptr<interface> mk_bd_interface(
        const opflexagent::Endpoint &ep,
        const std::shared_ptr<bridge_domain> bd,
        const std::shared_ptr<route_domain> rd) throw(NoEpInterfaceException);

    /**
     * Referene to runtime data.
     */
    Runtime &m_runtime;
};

}; // namespace VPP
