/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2017-2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __VPP_SPINE_PROXY_H__
#define __VPP_SPINE_PROXY_H__

#include <boost/asio/ip/address.hpp>

namespace VOM
{
class vxlan_tunnel;
};

namespace VPP
{
/**
 * A representation of the Spine prxy where unknown unicast packets are sent
 */
class SpineProxy
{
  public:
    /**
     */
    SpineProxy(const boost::asio::ip::address_v4 &local,
               const boost::asio::ip::address_v4 &remote_v4,
               const boost::asio::ip::address_v4 &remote_v6,
               const boost::asio::ip::address_v4 &remote_mac);

    const std::shared_ptr<VOM::vxlan_tunnel> mk_v4(const std::string &key, uint32_t vnid);
    const std::shared_ptr<VOM::vxlan_tunnel> mk_v6(const std::string &key, uint32_t vnid);
    const std::shared_ptr<VOM::vxlan_tunnel> mk_mac(const std::string &key, uint32_t vnid);

  private:
    const std::shared_ptr<VOM::vxlan_tunnel>
    mk_intf(const std::string &key,
            boost::asio::ip::address_v4 &src,
            boost::asio::ip::address_v4 &dst,
            uint32_t vnid);

    boost::asio::ip::address_v4 m_local;
    boost::asio::ip::address_v4 m_remote_v4;
    boost::asio::ip::address_v4 m_remote_v6;
    boost::asio::ip::address_v4 m_remote_mac;
};
}; // namespace VPP

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */

#endif
