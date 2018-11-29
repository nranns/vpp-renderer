/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "VppCrossConnect.h"

#include <opflexagent/logging.h>

#include "vom/interface.hpp"
#include "vom/l2_xconnect.hpp"
#include "vom/sub_interface.hpp"
#include "vom/tap_interface.hpp"

using namespace VOM;

namespace VPP {

static const std::string XCONNECT_KEY = "__xconnect__";

CrossConnect::xconnect_t::xconnect_t(const std::string& name,
                                     uint16_t vlan,
                                     std::string ip_address)
    : name(name)
    , vlan(vlan)
    , ip(boost::asio::ip::address::from_string(ip_address))
{}

std::string CrossConnect::xconnect_t::to_string() const
{
  std::ostringstream s;
  s << "[itf:" << name << " vlan:" << vlan << " ip:" << ip.to_string() << "]";

  return (s.str());
}

CrossConnect::CrossConnect()
{}


void CrossConnect::insert_xconnect(CrossConnect::xconnect xconn)
{
    this->xconnects.push_back(xconn);
}

static VOM::interface::type_t getIntfTypeFromName(std::string& name) {
    if (name.find("Bond") != std::string::npos)
        return VOM::interface::type_t::BOND;
    else if (name.find("Ethernet") != std::string::npos)
        return VOM::interface::type_t::ETHERNET;
    else if (name.find("tapv2") != std::string::npos)
        return VOM::interface::type_t::TAPV2;

    return VOM::interface::type_t::AFPACKET;
}

void CrossConnect::configure_xconnect()
{

    for (auto it : xconnects) {
        std::shared_ptr<interface> itf_ptr, xitf_ptr;
        VOM::interface::type_t type = getIntfTypeFromName(it.first.name);
        if (type == VOM::interface::type_t::TAPV2) {
            VOM::route::prefix_t pfx(it.first.ip, 24);
            tap_interface itf(it.first.name, interface::admin_state_t::UP, pfx);
            OM::write(XCONNECT_KEY, itf);
            itf_ptr = itf.singular();
        } else {
            interface itf(it.first.name, type, interface::admin_state_t::UP);
            OM::write(XCONNECT_KEY, itf);
            itf_ptr = itf.singular();
        }
        if (it.first.vlan) {
            /*
             * now create the sub-interface on which control and data traffic from
             * the upstream will arrive
             */
            sub_interface subitf(*itf_ptr, interface::admin_state_t::UP, it.first.vlan);
            OM::write(XCONNECT_KEY, subitf);
            itf_ptr = subitf.singular();
        }
        VOM::interface::type_t type2 = getIntfTypeFromName(it.second.name);
        if (type2 == VOM::interface::type_t::TAPV2) {
            VOM::route::prefix_t pfx(it.second.ip, 24);
            tap_interface xitf(it.second.name, interface::admin_state_t::UP, pfx);
            OM::write(XCONNECT_KEY, xitf);
            xitf_ptr = xitf.singular();
        } else {
            interface xitf(it.second.name, type2, interface::admin_state_t::UP);
            OM::write(XCONNECT_KEY, xitf);
            xitf_ptr = xitf.singular();
        }
        if (it.second.vlan) {
            /*
             * now create the sub-interface on which control and data traffic from
             * the upstream will arrive
             */
            sub_interface xsubitf(*xitf_ptr, interface::admin_state_t::UP, it.second.vlan);
            OM::write(XCONNECT_KEY, xsubitf);
            xitf_ptr = xsubitf.singular();
        }
        VOM::l2_xconnect l2_xconn(*itf_ptr, *xitf_ptr);
        OM::write(XCONNECT_KEY, l2_xconn);
    }
}

} // namespace VPP

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */
