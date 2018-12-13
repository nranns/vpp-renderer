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

#include "VppRuntime.hpp"

namespace VOM
{
class gbp_endpoint_group;
};

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
    struct NoFowardInfoException
    {
    };

    EndPointGroupManager(Runtime &runtime);

    static ForwardInfo
    get_fwd_info(Runtime &r,
                 const opflex::modb::URI &uri) throw(NoFowardInfoException);

    void handle_update(const opflex::modb::URI &epgURI);

    static std::shared_ptr<VOM::gbp_endpoint_group>
    mk_group(Runtime &r, const std::string &key, const opflex::modb::URI &uri);

  private:
    /**
     * Referene to runtime data.
     */
    Runtime &m_runtime;
};
};

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */
