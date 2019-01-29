/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <string>

#include "VppUtil.hpp"

namespace VPP
{
const interface::type_t &
getIntfTypeFromName(const std::string &name)
{
    if (name.find("Bond") != std::string::npos)
        return interface::type_t::BOND;
    else if (name.find("Ethernet") != std::string::npos)
        return interface::type_t::ETHERNET;
    else if ((name.find("tapv2") != std::string::npos) ||
             (name.find("tap") != std::string::npos))
        return interface::type_t::TAPV2;
    else if ((name.find("vhost") != std::string::npos) ||
             (name.find("vhu") != std::string::npos))
        return interface::type_t::VHOST;

    return interface::type_t::AFPACKET;
}

boost::optional<mac_address_t>
mac_from_modb(boost::optional<const opflex::modb::MAC&> mo)
{
  if (!mo)
    return boost::none;

  return (mac_address_t(mo->toString()));
}

}; // namespace VPP

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */
