/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __VPP_ID_GEN_H__
#define __VPP_ID_GEN_H__

#include <opflexagent/IdGenerator.h>

namespace VPP
{
class IdGen
{
  public:
    IdGen(opflexagent::IdGenerator &idGen);

    uint32_t get(opflex::modb::class_id_t cid, const opflex::modb::URI &uri);

    void erase(opflex::modb::class_id_t cid, const opflex::modb::URI &uri);

  private:
    const char *get_namespace(opflex::modb::class_id_t cid);

    opflexagent::IdGenerator &m_id_gen;
};

} // namespace VPP

#endif

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */
