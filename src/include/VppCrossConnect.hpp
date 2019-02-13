/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2017-2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef OPFLEXAGNET_VPPCROSSCONNECT_H__
#define OPFLEXAGENT_VPPCROSSCONNECT_H__

#include <list>

#include <boost/asio/ip/address.hpp>

namespace VPP
{
/**
 * A description of the cross connect class.
 * It will be used for storage, management of storage etc.
 */
class CrossConnect
{
  public:
    /**
     * Default Constructor
     */
    CrossConnect();

    struct xconnect_t
    {
        xconnect_t(const std::string &name,
                   uint16_t vlan = 0,
                   std::string ip_address = "",
                   std::string tag_rewrite = "");
        std::string to_string() const;
        std::string name;
        uint16_t vlan;
        boost::asio::ip::address ip;
        std::string tag_rewrite;
    };

    typedef std::pair<xconnect_t, xconnect_t> xconnect;

    /**
     * insert the cross connect interfaces
     */
    void insert_xconnect(xconnect xconn);

    /**
     * configure cross connect on interfaces
     */
    void configure_xconnect();

  private:
    /**
     * The cross connect pairs set
     */
    std::list<xconnect> xconnects;
};
}; // namespace VPP

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */

#endif
