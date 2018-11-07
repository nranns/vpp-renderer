/*
 * Test suite for VPPRenderer
 *
 * Copyright (c) 2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <boost/test/unit_test.hpp>

#include <opflexagent/test/ModbFixture.h>

#include "VPPRenderer.h"

BOOST_AUTO_TEST_SUITE(VPPRenderer_test)

class MockCmdQ : public VOM::HW::cmd_q {
public:
    MockCmdQ() {}
    ~MockCmdQ() {}
};

class MockVppManager : public opflexagent::VppManager {
public:
    MockVppManager(Agent& agent, IdGenerator& idGen, VOM::HW::cmd_q* q) :
                   VppManager(agent, idGen, q) {}
    ~MockVppManager() {}

    void start() {
        std::cout<< " starting Mock vpp manager" << std::endl;
    }
    void registerModbListeners() {
        std::cout<< " registering Mock ModbListeners" << std::endl;
    }
    void stop() {
        std::cout<< " stopping Mock vpp manager" << std::endl;
    }
};

BOOST_FIXTURE_TEST_CASE(vpp, opflexagent::ModbFixture) {

    IdGenerator *idGen = new IdGenerator();
    VOM::HW::cmd_q *vppQ =  new MockCmdQ();
    VppManager *vppManager = new MockVppManager(agent, *idGen, vppQ);
    vpprenderer::VPPRenderer vpp(agent, idGen, vppQ, vppManager);
    vpp.start();
    vpp.stop();
}

BOOST_AUTO_TEST_SUITE_END()
