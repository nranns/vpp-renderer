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

namespace VPP
{
/**
 * A representation of the Spine prxy where unknown unicast packets are sent
 */
class SpineProxy
{
  public:
    /**
     * Default Constructor
     */
    SpineProxy(const boost::asio::ip::address_v4 &local,
               const boost::asio::ip::address_v4 &remote_v4,
               const boost::asio::ip::address_v4 &remote_v6,
               const boost::asio::ip::address_v4 &remote_mac);

  private:
};
}; // namespace VPP

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */

#endif
