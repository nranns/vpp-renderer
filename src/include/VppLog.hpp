/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __VPP_LOG_H__
#define __VPP_LOG_H__

#include <opflexagent/logging.h>

#define OLOGD LOG(opflexagent::DEBUG)
#define OLOGW LOG(opflexagent::WARNING)
#define VLOGI LOG(opflexagent::INFO)
#define VLOGE LOG(opflexagent::ERROR)

#endif

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */
