/*
 * Test suite for VppRenderer
 *
 * Copyright (c) 2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <boost/test/unit_test.hpp>

#include <opflexagent/test/ModbFixture.h>

#include "VppRenderer.hpp"

BOOST_AUTO_TEST_SUITE(VppRenderer_test)

class MockCmdQ : public VOM::HW::cmd_q
{
  public:
    MockCmdQ() = default;
    ~MockCmdQ() = default;
};
class MockStatReader : public VOM::stat_reader
{
  public:
    MockStatReader() = default;
    ~MockStatReader() = default;
};

class MockVppManager : public VPP::VppManager
{
  public:
    MockVppManager(Agent &agent,
                   IdGenerator &idGen,
                   VOM::HW::cmd_q *q,
                   VOM::stat_reader *sr)
        : VppManager(agent, idGen, q, sr)
    {
    }
    ~MockVppManager()
    {
    }

    void
    start()
    {
        std::cout << " starting Mock vpp manager" << std::endl;
    }
    void
    registerModbListeners()
    {
        std::cout << " registering Mock ModbListeners" << std::endl;
    }
    void
    stop()
    {
        std::cout << " stopping Mock vpp manager" << std::endl;
    }
};

BOOST_FIXTURE_TEST_CASE(vpp, opflexagent::ModbFixture)
{

    IdGenerator *idGen = new IdGenerator();
    VOM::HW::cmd_q *vppQ = new MockCmdQ();
    VOM::stat_reader *vppSR = new MockStatReader();
    VPP::VppManager *vppManager =
        new MockVppManager(agent, *idGen, vppQ, vppSR);
    VPP::VppRenderer vpp(agent, *idGen, vppManager);
    vpp.start();
    vpp.stop();
}

BOOST_AUTO_TEST_SUITE_END()
