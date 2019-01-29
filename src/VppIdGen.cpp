/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "VppIdGen.hpp"

#include <modelgbp/gbp/BridgeDomain.hpp>
#include <modelgbp/gbp/Contract.hpp>
#include <modelgbp/gbp/FloodDomain.hpp>
#include <modelgbp/gbp/L3ExternalNetwork.hpp>
#include <modelgbp/gbp/RoutingDomain.hpp>

namespace VPP
{
static const char *ID_NAMESPACES[] = {"floodDomain",
                                      "bridgeDomain",
                                      "routingDomain",
                                      "contract",
                                      "externalNetwork",
                                      "secGroup",
                                      "secGroupSet"};

static const char *ID_NMSPC_FD = ID_NAMESPACES[0];
static const char *ID_NMSPC_BD = ID_NAMESPACES[1];
static const char *ID_NMSPC_RD = ID_NAMESPACES[2];
static const char *ID_NMSPC_CON = ID_NAMESPACES[3];
static const char *ID_NMSPC_EXTNET = ID_NAMESPACES[4];
static const char *ID_NMSPC_SECGROUP = ID_NAMESPACES[5];
static const char *ID_NMSPC_SECGROUP_SET = ID_NAMESPACES[6];

IdGen::IdGen(opflexagent::IdGenerator &id_gen)
    : m_id_gen(id_gen)
{
    for (size_t i = 0; i < sizeof(ID_NAMESPACES) / sizeof(char *); i++)
    {
        /*
         * start the namespace ID's at a non-zero offset so the
         * default tables are never used.
         */
        m_id_gen.initNamespace(ID_NAMESPACES[i], 100);
    }
}

uint32_t
IdGen::get(opflex::modb::class_id_t cid, const opflex::modb::URI &uri)
{
    return m_id_gen.getId(get_namespace(cid), uri.toString());
}

void
IdGen::erase(opflex::modb::class_id_t cid, const opflex::modb::URI &uri)
{
    m_id_gen.erase(get_namespace(cid), uri.toString());
}

const char *
IdGen::get_namespace(opflex::modb::class_id_t cid)
{
    const char *nmspc = NULL;
    switch (cid)
    {
    case modelgbp::gbp::RoutingDomain::CLASS_ID:
        nmspc = ID_NMSPC_RD;
        break;
    case modelgbp::gbp::BridgeDomain::CLASS_ID:
        nmspc = ID_NMSPC_BD;
        break;
    case modelgbp::gbp::FloodDomain::CLASS_ID:
        nmspc = ID_NMSPC_FD;
        break;
    case modelgbp::gbp::Contract::CLASS_ID:
        nmspc = ID_NMSPC_CON;
        break;
    case modelgbp::gbp::L3ExternalNetwork::CLASS_ID:
        nmspc = ID_NMSPC_EXTNET;
        break;
    default:
        assert(false);
    }
    return nmspc;
}

/**
 * Get the VNID for the specified endpoint groups or L3 external
 * networks
 *
 * @param uris URIs of endpoint groups to search for
 * @param ids the corresponding set of vnids
 */
uint32_t
IdGen::get_ext_net_vnid(const opflex::modb::URI &uri)
{
    // External networks are assigned private VNIDs that have bit 31 (MSB)
    // set to 1. This is fine because legal VNIDs are 24-bits or less.
    return (get(modelgbp::gbp::L3ExternalNetwork::CLASS_ID, uri) | (1 << 31));
}

} // namespace VPP

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */
