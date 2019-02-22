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
class gbp_bridge_domain;
class bridge_domain;
class route_domain;
class vxlan_tunnel;
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
        NoFowardInfoException(std::string s):
            reason(s)
        {}

        std::string reason;
    };

    EndPointGroupManager(Runtime &runtime);

    static ForwardInfo
    get_fwd_info(Runtime &r,
                 const opflex::modb::URI &uri)
      throw(NoFowardInfoException);

    void handle_update(const opflex::modb::URI &epgURI);

    static std::shared_ptr<VOM::gbp_endpoint_group>
    mk_group(Runtime &r,
             const std::string &key,
             const opflex::modb::URI &uri);

    static std::shared_ptr<vxlan_tunnel>
    mk_mcast_tunnel(Runtime &r,
                    const std::string &key,
                    uint32_t vni,
                    const std::string &maddr);

    static std::shared_ptr<VOM::interface>
    mk_bvi(Runtime &r,
           const std::string &key,
           const VOM::bridge_domain &bd,
           const VOM::route_domain &rd,
           const boost::optional<mac_address_t> &mac = boost::none);

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
