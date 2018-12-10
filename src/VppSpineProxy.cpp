/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2017-2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <vom/om.hpp>
#include <vom/vxlan_tunnel.hpp>

#include "VppSpineProxy.hpp"

using namespace VOM;

namespace VPP
{
SpineProxy::SpineProxy(const boost::asio::ip::address_v4 &local,
                       const boost::asio::ip::address_v4 &remote_v4,
                       const boost::asio::ip::address_v4 &remote_v6,
                       const boost::asio::ip::address_v4 &remote_mac,
                       uint16_t vnid)
    : m_local(local)
    , m_remote_v4(remote_v4)
    , m_remote_v6(remote_v6)
    , m_remote_mac(remote_mac)
    , m_vnid(vnid)
{
}

const std::shared_ptr<VOM::vxlan_tunnel>
SpineProxy::mk_v4(const std::string &key)
{
    return (mk_intf(key, m_local, m_remote_v4, m_vnid));
}

const std::shared_ptr<VOM::vxlan_tunnel>
SpineProxy::mk_v6(const std::string &key)
{
    return (mk_intf(key, m_local, m_remote_v6, m_vnid));
}

const std::shared_ptr<VOM::vxlan_tunnel>
SpineProxy::mk_mac(const std::string &key)
{
    return (mk_intf(key, m_local, m_remote_mac, m_vnid));
}

const std::shared_ptr<VOM::vxlan_tunnel>
SpineProxy::mk_intf(const std::string &key,
                    boost::asio::ip::address_v4 &src,
                    boost::asio::ip::address_v4 &dst,
                    uint16_t vnid)
{
    std::shared_ptr<VOM::vxlan_tunnel> vt = std::make_shared<vxlan_tunnel>(
        src, dst, vnid, vxlan_tunnel::mode_t::GBP);
    OM::write(key, *vt);

    return vt;
}
};

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */
