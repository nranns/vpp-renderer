/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Test suite for class VppManager
 *
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <memory>

#include <boost/asio/ip/host_name.hpp>
#include <boost/optional.hpp>
#include <boost/test/unit_test.hpp>

#include <modelgbp/gbp/HashingAlgorithmEnumT.hpp>
#include <modelgbp/gbp/L3IfTypeEnumT.hpp>
#include <modelgbp/gbp/SecGroup.hpp>

#include <vom/acl_ethertype.hpp>
#include <vom/acl_l3_list.hpp>
#include <vom/acl_l2_list.hpp>
#include <vom/bridge_domain.hpp>
#include <vom/bridge_domain_arp_entry.hpp>
#include <vom/bridge_domain_entry.hpp>
#include <vom/dhcp_client.hpp>
#include <vom/gbp_contract.hpp>
#include <vom/gbp_endpoint.hpp>
#include <vom/gbp_endpoint_group.hpp>
#include <vom/gbp_ext_itf.hpp>
#include <vom/gbp_subnet.hpp>
#include <vom/gbp_vxlan.hpp>
#include <vom/hw.hpp>
#include <vom/igmp_binding.hpp>
#include <vom/igmp_listen.hpp>
#include <vom/inspect.hpp>
#include <vom/interface.hpp>
#include <vom/interface_cmds.hpp>
#include <vom/l2_binding.hpp>
#include <vom/l2_emulation.hpp>
#include <vom/l3_binding.hpp>
#include <vom/lldp_binding.hpp>
#include <vom/lldp_global.hpp>
#include <vom/nat_binding.hpp>
#include <vom/nat_static.hpp>
#include <vom/neighbour.hpp>
#include <vom/route.hpp>
#include <vom/route_domain.hpp>
#include <vom/stat_reader.hpp>
#include <vom/sub_interface.hpp>

#include "VppManager.hpp"
#include "opflexagent/test/ModbFixture.h"
#include <opflexagent/logging.h>

using namespace VOM;
using namespace opflexagent;
using boost::asio::ip::address;
using boost::asio::ip::address_v4;

BOOST_AUTO_TEST_SUITE(vpp)

struct MockStatReader : public stat_reader
{
    int
    connect()
    {
    }

    void
    disconnect()
    {
    }

    void
    read()
    {
    }
};

class MockCmdQ : public HW::cmd_q
{
  public:
    MockCmdQ()
        : handle(0)
        , m_mutex()
    {
    }
    ~MockCmdQ()
    {
    }

    void
    enqueue(cmd *c)
    {
        std::shared_ptr<cmd> sp(c);
        m_cmds.push(sp);
    }
    void
    enqueue(std::queue<cmd *> &cmds)
    {
        cmd *c;

        while (!cmds.empty())
        {
            c = cmds.front();
            cmds.pop();

            std::shared_ptr<cmd> sp(c);
            m_cmds.push(sp);
        }
    }
    void
    enqueue(std::shared_ptr<cmd> c)
    {
        m_cmds.push(c);
    }

    void
    dequeue(cmd *f)
    {
    }

    void
    dequeue(std::shared_ptr<cmd> cmd)
    {
    }

    rc_t
    write()
    {
        /*
         * the unit tests are executed in thread x and the VppManager
         * task queue executes in thread y. both call write() when
         * objects are destroyed, even though the objects in the
         * test case do not issue commands. Which thread runs write
         * is not important.
         * N.B. this is an artefact of the way the unit-tests are
         * structered and run, this does not afflict the real system
         * where *all* objects are created and destroyed with the
         * VppManager taskQueue context.
         */
        std::lock_guard<std::mutex> lg(m_mutex);

        std::shared_ptr<cmd> c;

        while (!m_cmds.empty())
        {
            c = m_cmds.front();
            m_cmds.pop();
            handle_cmd(c.get());
        }

        return (rc_t::OK);
    }

    /**
     * Blocking Connect to VPP - call once at bootup
     */
    bool
    connect()
    {
        return true;
    }

    void
    disconnect()
    {
    }

  private:
    void
    handle_cmd(cmd *c)
    {
        {
            auto ac =
                dynamic_cast<interface::create_cmd<vapi::Af_packet_create> *>(
                    c);
            if (NULL != ac)
            {
                HW::item<handle_t> res(++handle, rc_t::OK);
                ac->item() = res;
            }
        }
        {
            auto ac =
                dynamic_cast<interface::create_cmd<vapi::Create_vlan_subif> *>(
                    c);
            if (NULL != ac)
            {
                HW::item<handle_t> res(++handle, rc_t::OK);
                ac->item() = res;
            }
        }

        c->succeeded();
    }
    uint32_t handle;

    std::mutex m_mutex;

    std::queue<std::shared_ptr<cmd>> m_cmds;
};

template <typename T>
bool
is_match(const T &expected)
{
    std::shared_ptr<T> actual = T::find(expected.key());

    if (!actual) return false;

    return (expected == *actual);
}

template <typename T>
bool
is_present(const T &search)
{
    std::shared_ptr<T> actual = T::find(search.key());

    if (!actual) return false;

    return (true);
}

#define WAIT_FOR1(stmt) WAIT_FOR((stmt), 100)

template <typename T>
static void
print_obj(const T &obj, const std::string &s)
{
    LOG(ERROR) << s << obj.to_string();
}

#define WAIT_FOR_MATCH(obj)                                                    \
    WAIT_FOR_ONFAIL(is_match(obj), 100, print_obj(obj, "Not Found: "))
#define WAIT_FOR_NOT_PRESENT(obj)                                              \
    WAIT_FOR_ONFAIL(!is_present(obj), 100, print_obj(obj, "Still present: "))

class VppManagerFixture : public ModbFixture
{
  public:
    typedef opflex::ofcore::OFConstants::OpflexElementMode opflex_elem_t;

  public:
    VppManagerFixture(opflex_elem_t mode = opflex_elem_t::INVALID_MODE)
        : ModbFixture(mode)
        , vMac{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
        , policyMgr(agent.getPolicyManager())
        , vppQ()
        , vppSR()
        , vppManager(agent, idGen, &vppQ, &vppSR)
        , inspector()
    {
        createVppObjects();
        WAIT_FOR(policyMgr.groupExists(epg0->getURI()), 500);
        WAIT_FOR(policyMgr.getBDForGroup(epg0->getURI()) != boost::none, 500);

        WAIT_FOR(policyMgr.groupExists(epg1->getURI()), 500);
        WAIT_FOR(policyMgr.getRDForGroup(epg1->getURI()) != boost::none, 500);

        vppManager.uplink().set("opflex-itf", 4093, "opflex-host");
        vppManager.setVirtualRouter(true, true, vMac.to_string());
    }

    virtual ~VppManagerFixture()
    {
        vppManager.stop();
        agent.stop();
    }

    void
    createVppObjects()
    {
        using opflex::modb::Mutator;
        using namespace modelgbp;
        using namespace modelgbp::gbp;
        using namespace modelgbp::gbpe;

        /*
         * create EPGs and forwarding objects
         * VPP Rnederer support the opnstack variant of the opflex model
         * one EPG per-BD, one subnet per BD.
         */
        Mutator mutator(framework, policyOwner);
        config = universe->addPlatformConfig("default");
        config->setMulticastGroupIP("224.1.1.1");

        fd0 = space->addGbpFloodDomain("fd0");
        fd0->setUnknownFloodMode(UnknownFloodModeEnumT::CONST_HWPROXY);
        fd1 = space->addGbpFloodDomain("fd1");
        fd1->setUnknownFloodMode(UnknownFloodModeEnumT::CONST_FLOOD);
        bd0 = space->addGbpBridgeDomain("bd0");
        bd0->addGbpeInstContext()->setEncapId(0xAA);
        bd0->addGbpeInstContext()->setMulticastGroupIP("224.1.1.1");

        bd1 = space->addGbpBridgeDomain("bd1");
        rd0 = space->addGbpRoutingDomain("rd0");
        rd0->addGbpeInstContext()->setEncapId(0xBB);

        fd0->addGbpFloodDomainToNetworkRSrc()->setTargetBridgeDomain(
            bd0->getURI());
        fd0ctx = fd0->addGbpeFloodContext();
        fd1->addGbpFloodDomainToNetworkRSrc()->setTargetBridgeDomain(
            bd1->getURI());

        bd0->addGbpBridgeDomainToNetworkRSrc()->setTargetRoutingDomain(
            rd0->getURI());
        bd1->addGbpBridgeDomainToNetworkRSrc()->setTargetRoutingDomain(
            rd0->getURI());

        subnetsfd0 = space->addGbpSubnets("subnetsfd0");
        subnetsfd0_1 = subnetsfd0->addGbpSubnet("subnetsfd0_1");
        subnetsfd0_1->setAddress("10.20.44.1")
            .setPrefixLen(24)
            .setVirtualRouterIp("10.20.44.1");
        subnetsfd0_2 = subnetsfd0->addGbpSubnet("subnetsfd0_2");
        subnetsfd0_2->setAddress("2001:db8::")
            .setPrefixLen(32)
            .setVirtualRouterIp("2001:db8::1");
        fd0->addGbpForwardingBehavioralGroupToSubnetsRSrc()->setTargetSubnets(
            subnetsfd0->getURI());
        rd0->addGbpRoutingDomainToIntSubnetsRSrc(
            subnetsfd0->getURI().toString());

        subnetsfd1 = space->addGbpSubnets("subnetsfd1");
        subnetsfd1_1 = subnetsfd0->addGbpSubnet("subnetsfd1_1");
        subnetsfd1_1->setAddress("10.20.45.0")
            .setPrefixLen(24)
            .setVirtualRouterIp("10.20.45.1");
        fd1->addGbpForwardingBehavioralGroupToSubnetsRSrc()->setTargetSubnets(
            subnetsfd1->getURI());
        rd0->addGbpRoutingDomainToIntSubnetsRSrc(
            subnetsfd1->getURI().toString());

        epg0 = space->addGbpEpGroup("epg0");
        epg0->addGbpEpGroupToNetworkRSrc()->setTargetBridgeDomain(
            bd0->getURI());
        epg0->addGbpEpGroupToNetworkRSrc()
            ->setTargetFloodDomain(fd0->getURI());
        epg0->addGbpeInstContext()->setEncapId(0xA0A);
        epg0->addGbpeInstContext()->setClassid(0xBA);

        epg1 = space->addGbpEpGroup("epg1");
        epg1->addGbpEpGroupToNetworkRSrc()->setTargetBridgeDomain(
            bd1->getURI());
        epg1->addGbpeInstContext()->setEncapId(0xA0B);

        epg2 = space->addGbpEpGroup("epg2");
        epg3 = space->addGbpEpGroup("epg3");

        /*
         * L3Out objects
         */
        ext_rd0 = space->addGbpRoutingDomain("ext_rd0");
        ext_rd0->addGbpeInstContext()->setEncapId(1122);
        ext_dom = ext_rd0->addGbpL3ExternalDomain("ext_dom0");
        ext_net0 = ext_dom->addGbpL3ExternalNetwork("ext_dom0_net0");
        ext_net0->addGbpeInstContext()->setClassid(1234);
        ext_net0->addGbpExternalSubnet("ext_dom0_net0_sub0")
            ->setAddress("105.0.0.0")
            .setPrefixLen(24);
        ext_net0->addGbpExternalSubnet("ext_dom0_net0_sub1")
            ->setAddress("106.0.0.0")
            .setPrefixLen(24);
        ext_net1 = ext_dom->addGbpL3ExternalNetwork("ext_dom1_net0");
        ext_net1->addGbpeInstContext()->setClassid(1235);
        ext_net1->addGbpExternalSubnet("ext_dom0_net1_sub0")
            ->setAddress("107.0.0.0")
            .setPrefixLen(24);
        ext_net1->addGbpExternalSubnet("ext_dom0_net1_sub1")
            ->setAddress("108.0.0.0")
            .setPrefixLen(24);
        ext_bd0 = space->addGbpExternalL3BridgeDomain("ext_bd0");
        ext_bd0->addGbpeInstContext()->setEncapId(1133);
        ext_bd0->addGbpeInstContext()->setMulticastGroupIP("224.1.2.2");
        ext_bd0->addGbpExternalL3BridgeDomainToVrfRSrc()->
            setTargetRoutingDomain(ext_rd0->getURI());
        ext_node0 = space->addGbpExternalNode("ext_node0");
        ext_itf0 = space->addGbpExternalInterface("ext_itf0");
        ext_itf0->setAddress("10.30.0.1");
        ext_itf0->setPrefixLen(24);
        ext_itf0->setEncap(1144);
        ext_itf0->setMac(opflex::modb::MAC("00:00:00:00:80:00"));
        ext_itf0->setIfInstT(L3IfTypeEnumT::CONST_EXTSVI);
        ext_itf0->addGbpExternalInterfaceToExtl3bdRSrc()->
            setTargetExternalL3BridgeDomain(ext_bd0->getURI());
        ext_itf0->addGbpExternalInterfaceToL3outRSrc()->
            setTargetL3ExternalDomain(ext_dom->getURI());

        static_route1 = ext_node0->addGbpStaticRoute("static_route1");
        static_route1->addGbpStaticRouteToVrfRSrc()->
            setTargetRoutingDomain(ext_rd0->getURI());
        static_route1->setAddress("101.101.0.0");
        static_route1->setPrefixLen(16);
        static_route1->addGbpStaticNextHop("100.100.100.2");
        static_nh1 = static_route1->addGbpStaticNextHop("100.100.100.3");
        static_route1->addGbpStaticNextHop("100.100.100.4");

        mutator.commit();

        /* create endpoints */
        ep0.reset(new Endpoint("0-0-0-0"));
        ep0->setInterfaceName("port80");
        ep0->setMAC(opflex::modb::MAC("00:00:00:00:80:00"));
        ep0->addIP("10.20.44.2");
        ep0->addIP("10.20.44.3");
        ep0->addIP("2001:db8::2");
        ep0->addIP("2001:db8::3");
        ep0->addAnycastReturnIP("10.20.44.2");
        ep0->addAnycastReturnIP("2001:db8::2");
        ep0->setEgURI(epg0->getURI());
        epSrc.updateEndpoint(*ep0);

        ep1.reset(new Endpoint("0-0-0-1"));
        ep1->setMAC(opflex::modb::MAC("00:00:00:00:00:01"));
        ep1->addIP("10.20.45.21");
        ep1->setEgURI(epg0->getURI());
        epSrc.updateEndpoint(*ep1);

        ep2.reset(new Endpoint("0-0-0-2"));
        ep2->setMAC(opflex::modb::MAC("00:00:00:00:00:02"));
        ep2->addIP("10.20.45.21");
        ep2->setInterfaceName("port11");
        ep2->setEgURI(epg1->getURI());
        epSrc.updateEndpoint(*ep2);

        ep3.reset(new Endpoint("0-0-0-3"));
        ep3->setMAC(opflex::modb::MAC("00:00:00:00:00:03"));
        ep3->addIP("10.20.45.31");
        ep3->setInterfaceName("eth3");
        ep3->setEgURI(epg1->getURI());
        epSrc.updateEndpoint(*ep3);

        ep4.reset(new Endpoint("0-0-0-4"));
        ep4->setMAC(opflex::modb::MAC("00:00:00:00:00:04"));
        ep4->addIP("10.20.45.41");
        ep4->setInterfaceName("port40");
        ep4->setAccessIfaceVlan(1000);
        ep4->setEgURI(epg1->getURI());
        epSrc.updateEndpoint(*ep4);

        ext_ep0.reset(new Endpoint("0-0-e-0"));
        ext_ep0->setMAC(opflex::modb::MAC("00:00:00:00:0E:00"));
        ext_ep0->addIP("10.30.0.2");
        ext_ep0->setInterfaceName("port-e-00");
        ext_ep0->setEgURI(ext_itf0->getURI());
        ext_ep0->setExtInterfaceURI(ext_itf0->getURI());
        ext_ep0->setExtNodeURI(ext_node0->getURI());
        epSrc.updateEndpoint(*ext_ep0);
    }

    void
    createNatObjects()
    {
        using std::shared_ptr;
        using namespace modelgbp::gbp;
        using namespace opflex::modb;

        shared_ptr<modelgbp::policy::Space> common;
        shared_ptr<FloodDomain> fd_ext;
        shared_ptr<BridgeDomain> bd_ext;
        shared_ptr<Subnets> subnets_ext;
        shared_ptr<L3ExternalDomain> l3ext;

        Mutator mutator(framework, policyOwner);
        common = universe->addPolicySpace("common");
        bd_ext = common->addGbpBridgeDomain("bd_ext");
        rd_ext = common->addGbpRoutingDomain("rd_ext");
        fd_ext = common->addGbpFloodDomain("fd_ext");

        fd_ext->addGbpFloodDomainToNetworkRSrc()->setTargetBridgeDomain(
            bd_ext->getURI());
        bd_ext->addGbpBridgeDomainToNetworkRSrc()->setTargetRoutingDomain(
            rd_ext->getURI());

        subnets_ext = common->addGbpSubnets("subnets_ext");
        subnets_ext->addGbpSubnet("subnet_ext4")
            ->setAddress("5.5.5.0")
            .setPrefixLen(24);

        bd_ext->addGbpForwardingBehavioralGroupToSubnetsRSrc()
            ->setTargetSubnets(subnets_ext->getURI());
        rd_ext->addGbpRoutingDomainToIntSubnetsRSrc(
            subnets_ext->getURI().toString());

        epg_nat = common->addGbpEpGroup("nat-epg");
        epg_nat->addGbpeInstContext()->setEncapId(0x424);
        epg_nat->addGbpEpGroupToNetworkRSrc()->setTargetFloodDomain(
            fd_ext->getURI());

        l3ext = rd0->addGbpL3ExternalDomain("ext");
        l3ext_net = l3ext->addGbpL3ExternalNetwork("outside");
        l3ext_net->addGbpExternalSubnet("outside")
            ->setAddress("5.5.0.0")
            .setPrefixLen(16);
        mutator.commit();

        Endpoint::IPAddressMapping ipm4("91c5b217-d244-432c-922d-533c6c036ab3");
        ipm4.setMappedIP("10.20.44.2");
        ipm4.setFloatingIP("5.5.5.5");
        ipm4.setEgURI(epg_nat->getURI());
        ep0->addIPAddressMapping(ipm4);
        epSrc.updateEndpoint(*ep0);

        WAIT_FOR(policyMgr.getRDForGroup(epg_nat->getURI()) != boost::none,
                 500);
        PolicyManager::subnet_vector_t sns;
        WAIT_FOR_DO(sns.size() == 1, 500, sns.clear();
                    policyMgr.getSubnetsForGroup(epg_nat->getURI(), sns));
    }

    void
    assignEpg0ToFd0()
    {
        PolicyManager::subnet_vector_t sns;
        opflex::modb::Mutator mutator(framework, policyOwner);
        epg0->addGbpEpGroupToNetworkRSrc()->setTargetFloodDomain(fd0->getURI());
        mutator.commit();

        WAIT_FOR1(policyMgr.getFDForGroup(epg0->getURI()) != boost::none);
        WAIT_FOR_DO(sns.size() == 3, 500, sns.clear();
                    policyMgr.getSubnetsForGroup(epg0->getURI(), sns));
        WAIT_FOR1(
            (PolicyManager::getRouterIpForSubnet(*sns[1]) != boost::none));
    }

    void
    do_dhcp()
    {
        host = boost::asio::ip::address::from_string("192.168.1.1");
        router = boost::asio::ip::address::from_string("192.168.1.2");

        route::prefix_t pfx(host, 24);
        mac_address_t mac("00:00:11:22:33:44");

        /*
         * boot phase so the VPP/host address is learnt
         */
        interface v_phy("opflex-itf",
                        interface::type_t::AFPACKET,
                        interface::admin_state_t::UP);
        sub_interface v_sub(v_phy, interface::admin_state_t::UP, 4093);

        WAIT_FOR_MATCH(v_phy);
        WAIT_FOR_MATCH(v_sub);

        std::string fqdn = boost::asio::ip::host_name();
        WAIT_FOR_MATCH(dhcp_client(v_sub, fqdn));
        WAIT_FOR_MATCH(lldp_global(fqdn, 5, 2));
        WAIT_FOR_MATCH(lldp_binding(v_phy, "uplink-interface"));

        std::shared_ptr<dhcp_client::lease_t> lease =
          std::make_shared<dhcp_client::lease_t>(dhcp_client::state_t::BOUND,
                                                 v_sub.singular(),
                                                 router,
                                                 pfx,
                                                 boost::asio::ip::host_name(),
                                                 mac);

        vppManager.uplink().handle_dhcp_event(lease);
    }

    void
    removeEpg(std::shared_ptr<modelgbp::gbp::EpGroup> epg)
    {
        opflex::modb::Mutator m2(framework, policyOwner);
        epg->remove();
        m2.commit();
        WAIT_FOR1(!policyMgr.groupExists(epg->getURI()));
    }

    std::vector<boost::asio::ip::address>
    getEPIps(std::shared_ptr<Endpoint> ep)
    {
        std::vector<boost::asio::ip::address> ipAddresses;
        boost::system::error_code ec;

        for (const std::string &ipStr : ep->getIPs())
        {
            boost::asio::ip::address addr =
                boost::asio::ip::address::from_string(ipStr, ec);
            if (!ec)
            {
                ipAddresses.push_back(addr);
            }
        }

        return ipAddresses;
    }

    address host, router;
    std::shared_ptr<Endpoint> ep5, ext_ep0;
    std::shared_ptr<modelgbp::gbp::BridgeDomain> bd2;
    std::shared_ptr<modelgbp::gbp::EpGroup> epg_nat;
    std::shared_ptr<modelgbp::gbp::L3ExternalNetwork> l3ext_net;
    std::shared_ptr<modelgbp::gbp::RoutingDomain> rd_ext, ext_rd0;
    std::shared_ptr<modelgbp::gbp::ExternalNode> ext_node0;
    std::shared_ptr<modelgbp::gbp::ExternalL3BridgeDomain> ext_bd0;
    std::shared_ptr<modelgbp::gbp::ExternalInterface> ext_itf0;
    std::shared_ptr<modelgbp::gbp::StaticRoute> static_route1;
    std::shared_ptr<modelgbp::gbp::StaticNextHop> static_nh1;
    std::shared_ptr<modelgbp::gbp::L3ExternalDomain> ext_dom;
    std::shared_ptr<modelgbp::gbp::L3ExternalNetwork> ext_net0;
    std::shared_ptr<modelgbp::gbp::L3ExternalNetwork> ext_net1;

    mac_address_t vMac;
    PolicyManager &policyMgr;
    IdGenerator idGen;
    MockCmdQ vppQ;
    MockStatReader vppSR;

    VPP::VppManager vppManager;

    /**
     * To assist in checking the state that is present manually do
     *
     * inspector.handle_input("all", std::cout);
     *
     * in any of the test-cases
     */
    inspect inspector;
};

class VppStitchedManagerFixture : public VppManagerFixture
{
  public:
    VppStitchedManagerFixture()
    {
        vppManager.start();
    }
    ~VppStitchedManagerFixture()
    {
        vppManager.stop();
    }
};

class VppTransportManagerFixture : public VppManagerFixture
{
  public:
    VppTransportManagerFixture()
        : VppManagerFixture(opflex_elem_t::TRANSPORT_MODE)
    {
        framework.setElementMode(opflex::ofcore::OFConstants::OpflexElementMode::TRANSPORT_MODE);
        boost::system::error_code ec;
        boost::asio::ip::address_v4 proxyAddress;

        proxyAddress = boost::asio::ip::address_v4::from_string("44.44.44.44",ec);
        framework.setV4Proxy(proxyAddress);
        proxyAddress = boost::asio::ip::address_v4::from_string("66.66.66.66",ec);
        framework.setV6Proxy(proxyAddress);
        proxyAddress = boost::asio::ip::address_v4::from_string("55.55.55.55",ec);
        framework.setMacProxy(proxyAddress);
        vppManager.start();
    }
    ~VppTransportManagerFixture()
    {
        vppManager.stop();
    }
};

BOOST_FIXTURE_TEST_CASE(start, VppStitchedManagerFixture)
{
    /*
     * Validate the presence of the uplink state built at startup/boot
     *  - the physical unplink interface
     *  - the control VLAN sub-interface
     *  - DHCP configuration on the sub-interface
     *  - LLDP config on the physical interface
     */
    interface v_phy("opflex-itf",
                    interface::type_t::AFPACKET,
                    interface::admin_state_t::UP);
    sub_interface v_sub(v_phy, interface::admin_state_t::UP, 4093);

    WAIT_FOR_MATCH(v_phy);
    WAIT_FOR_MATCH(v_sub);

    std::string fqdn = boost::asio::ip::host_name();
    WAIT_FOR_MATCH(dhcp_client(v_sub, fqdn));
    WAIT_FOR_MATCH(lldp_global(fqdn, 5, 2));
    WAIT_FOR_MATCH(lldp_binding(v_phy, "uplink-interface"));
}

BOOST_FIXTURE_TEST_CASE(endpoint_group_add_del, VppStitchedManagerFixture)
{
    vppManager.egDomainUpdated(epg0->getURI());
    // vppManager.domainUpdated(modelgbp::gbp::RoutingDomain::CLASS_ID,
    //                         rd0->getURI());

    /*
     * Check for a bridge domain 100
     */
    bridge_domain v_bd_epg0(100, bridge_domain::learning_mode_t::OFF);
    WAIT_FOR_MATCH(v_bd_epg0);

    /*
     * check for the presence of a VOM route-domain matching the EPG's
     * ID's are offset by 100.
     */
    route_domain v_rd(100);
    WAIT_FOR_MATCH(v_rd);

    /*
     * After waiting for the route-domain to be created
     * all other state should now be present
     */

    /*
     * Find the BVI interface. the BVI's name includes the bridge-domain ID
     * the interface has a dependency on the route domain, so we 'new' the
     * interface so we can control its lifetime.
     */
    interface *v_bvi_epg0 = new interface(
        "bvi-100", interface::type_t::BVI, interface::admin_state_t::UP, v_rd);
    v_bvi_epg0->set(vMac);

    WAIT_FOR_MATCH(*v_bvi_epg0);

    /*
     * the BVI is put in the bridge-domain
     */
    WAIT_FOR_MATCH(l2_binding(*v_bvi_epg0, v_bd_epg0));

    /*
     * The EPG uplink interface, also bound to BD=1
     */
    interface v_phy("opflex-itf",
                    interface::type_t::AFPACKET,
                    interface::admin_state_t::UP);
    sub_interface v_upl_epg0(v_phy, interface::admin_state_t::UP, 0xA0A);
    WAIT_FOR_MATCH(v_upl_epg0);
    WAIT_FOR_MATCH(l2_binding(v_upl_epg0, v_bd_epg0));

    gbp_bridge_domain *v_gbd0 = new gbp_bridge_domain(v_bd_epg0, *v_bvi_epg0);
    WAIT_FOR_MATCH(*v_gbd0);

    gbp_endpoint_group *v_epg0 =
        new gbp_endpoint_group(0xA0A, v_upl_epg0, v_rd, *v_gbd0);
    WAIT_FOR_MATCH(*v_epg0);

    /*
     * Add EPG0 into FD0 to assign it subnets
     */
    assignEpg0ToFd0();
    vppManager.egDomainUpdated(epg0->getURI());

    /*
     * An entry in the L2FIB for the BVI
     */
    WAIT_FOR_MATCH(bridge_domain_entry(v_bd_epg0, vMac, *v_bvi_epg0));

    /*
     * check for an L3 binding and BD ARP for all of the router IPs
     */
    WAIT_FOR_MATCH(
        l3_binding(*v_bvi_epg0, {address::from_string("10.20.44.1")}));
    WAIT_FOR_MATCH(bridge_domain_arp_entry(
        v_bd_epg0, address::from_string("10.20.44.1"), vMac));
    WAIT_FOR_MATCH(
        l3_binding(*v_bvi_epg0, {address::from_string("2001:db8::1")}));
    WAIT_FOR_MATCH(bridge_domain_arp_entry(
        v_bd_epg0, address::from_string("2001:db8::1"), vMac));

    /*
     * there should be a route for each of those sub-nets via the epg-uplink
     */
    WAIT_FOR_MATCH(gbp_subnet(v_rd,
                              {address::from_string("10.20.44.0"), 24},
                              gbp_subnet::type_t::STITCHED_INTERNAL));
    WAIT_FOR_MATCH(gbp_subnet(v_rd,
                              {address::from_string("2001:db8::"), 32},
                              gbp_subnet::type_t::STITCHED_INTERNAL));

    /*
     * Routing-domain update. This should be a no-op change. Verify the subnets
     * still exist.
     */
    vppManager.domainUpdated(modelgbp::gbp::RoutingDomain::CLASS_ID,
                             rd0->getURI());
    WAIT_FOR_MATCH(gbp_subnet(v_rd,
                              {address::from_string("10.20.44.0"), 24},
                              gbp_subnet::type_t::STITCHED_INTERNAL));
    WAIT_FOR_MATCH(gbp_subnet(v_rd,
                              {address::from_string("2001:db8::"), 32},
                              gbp_subnet::type_t::STITCHED_INTERNAL));

    /*
     * Add a second group, same BD different RD
     */
    vppManager.egDomainUpdated(epg1->getURI());
    /* //assignEpg0ToFd0(sns); */

    bridge_domain v_bd_epg1(101, bridge_domain::learning_mode_t::OFF);
    WAIT_FOR_MATCH(v_bd_epg1);

    interface *v_bvi_epg1 = new interface(
        "bvi-101", interface::type_t::BVI, interface::admin_state_t::UP, v_rd);
    v_bvi_epg1->set(vMac);
    WAIT_FOR_MATCH(*v_bvi_epg1);

    sub_interface v_upl_epg1(v_phy, interface::admin_state_t::UP, 0xA0B);
    WAIT_FOR_MATCH(v_upl_epg1);
    WAIT_FOR_MATCH(l2_binding(v_upl_epg1, v_bd_epg1));
    gbp_bridge_domain *v_gbd1 = new gbp_bridge_domain(v_bd_epg1, *v_bvi_epg1);
    WAIT_FOR_MATCH(*v_gbd1);
    gbp_endpoint_group *v_epg1 =
        new gbp_endpoint_group(0xA0B, v_upl_epg1, v_rd, *v_gbd1);
    WAIT_FOR_MATCH(*v_epg1);

    WAIT_FOR_MATCH(gbp_subnet(v_rd,
                              {address::from_string("10.20.44.0"), 24},
                              gbp_subnet::type_t::STITCHED_INTERNAL));
    WAIT_FOR_MATCH(gbp_subnet(v_rd,
                              {address::from_string("10.20.45.0"), 24},
                              gbp_subnet::type_t::STITCHED_INTERNAL));
    WAIT_FOR_MATCH(gbp_subnet(v_rd,
                              {address::from_string("2001:db8::"), 32},
                              gbp_subnet::type_t::STITCHED_INTERNAL));

    /*
     * add a new subnet to the opflex route-domain
     * we expect the subnet to show up in each of the VPP RDs
     */
    opflex::modb::Mutator mutator(framework, policyOwner);
    std::shared_ptr<modelgbp::gbp::Subnet> subnetsfd1_2;
    subnetsfd1 = space->addGbpSubnets("subnetsfd1");
    subnetsfd1_2 = subnetsfd0->addGbpSubnet("subnetsfd1_2");
    subnetsfd1_2->setAddress("10.20.46.0").setPrefixLen(24);
    fd1->addGbpForwardingBehavioralGroupToSubnetsRSrc()->setTargetSubnets(
        subnetsfd1->getURI());
    rd0->addGbpRoutingDomainToIntSubnetsRSrc(subnetsfd1->getURI().toString());
    mutator.commit();
    vppManager.domainUpdated(modelgbp::gbp::RoutingDomain::CLASS_ID,
                             rd0->getURI());

    WAIT_FOR_MATCH(gbp_subnet(v_rd,
                              {address::from_string("10.20.44.0"), 24},
                              gbp_subnet::type_t::STITCHED_INTERNAL));
    WAIT_FOR_MATCH(gbp_subnet(v_rd,
                              {address::from_string("10.20.45.0"), 24},
                              gbp_subnet::type_t::STITCHED_INTERNAL));
    WAIT_FOR_MATCH(gbp_subnet(v_rd,
                              {address::from_string("10.20.46.0"), 24},
                              gbp_subnet::type_t::STITCHED_INTERNAL));
    WAIT_FOR_MATCH(gbp_subnet(v_rd,
                              {address::from_string("2001:db8::"), 32},
                              gbp_subnet::type_t::STITCHED_INTERNAL));

    /*
     * withdraw the route domain.
     */
    opflex::modb::Mutator m1(framework, policyOwner);
    rd0->remove();
    m1.commit();
    vppManager.domainUpdated(modelgbp::gbp::RoutingDomain::CLASS_ID,
                             rd0->getURI());

    /*
     * Withdraw the EPGs, all the state above should be gone
     */
    removeEpg(epg0);
    vppManager.egDomainUpdated(epg0->getURI());
    removeEpg(epg1);
    vppManager.egDomainUpdated(epg1->getURI());

    WAIT_FOR_NOT_PRESENT(gbp_subnet(v_rd,
                                    {address::from_string("10.20.44.0"), 24},
                                    gbp_subnet::type_t::STITCHED_INTERNAL));
    WAIT_FOR_NOT_PRESENT(gbp_subnet(v_rd,
                                    {address::from_string("10.20.45.0"), 24},
                                    gbp_subnet::type_t::STITCHED_INTERNAL));
    WAIT_FOR_NOT_PRESENT(gbp_subnet(v_rd,
                                    {address::from_string("10.20.46.0"), 24},
                                    gbp_subnet::type_t::STITCHED_INTERNAL));
    WAIT_FOR_NOT_PRESENT(gbp_subnet(v_rd,
                                    {address::from_string("2001:db8::"), 32},
                                    gbp_subnet::type_t::STITCHED_INTERNAL));

    WAIT_FOR_NOT_PRESENT(*v_epg0);
    delete v_epg0;
    WAIT_FOR_NOT_PRESENT(*v_epg1);
    delete v_epg1;

    WAIT_FOR_NOT_PRESENT(*v_gbd0);
    delete v_gbd0;
    WAIT_FOR_NOT_PRESENT(*v_gbd1);
    delete v_gbd1;

    WAIT_FOR_NOT_PRESENT(l2_binding(v_upl_epg0, v_bd_epg0));
    WAIT_FOR_NOT_PRESENT(l2_binding(*v_bvi_epg0, v_bd_epg0));
    WAIT_FOR_NOT_PRESENT(*v_bvi_epg0);
    delete v_bvi_epg0;

    WAIT_FOR_NOT_PRESENT(l2_binding(v_upl_epg1, v_bd_epg1));
    WAIT_FOR_NOT_PRESENT(l2_binding(*v_bvi_epg1, v_bd_epg1));
    WAIT_FOR_NOT_PRESENT(*v_bvi_epg1);
    delete v_bvi_epg1;

    /*
     * If the RDs have gone we can be sure the routes have too.
     */
    WAIT_FOR_NOT_PRESENT(v_upl_epg0);
    WAIT_FOR_NOT_PRESENT(v_bd_epg0);
    WAIT_FOR_NOT_PRESENT(v_upl_epg1);
    WAIT_FOR_NOT_PRESENT(v_bd_epg1);
    WAIT_FOR_NOT_PRESENT(v_rd);
}

BOOST_FIXTURE_TEST_CASE(endpoint_add_del, VppStitchedManagerFixture)
{
    assignEpg0ToFd0();
    vppManager.egDomainUpdated(epg0->getURI());
    vppManager.endpointUpdated(ep0->getUUID());

    mac_address_t v_mac_ep0("00:00:00:00:80:00");
    mac_address_t v_mac_ep2("00:00:00:00:00:02");
    mac_address_t v_mac_ep4("00:00:00:00:00:04");
    /*
     * Check for a bridge domain 100 and route domain 100.
     */
    bridge_domain v_bd_epg0(100, bridge_domain::learning_mode_t::OFF);
    WAIT_FOR_MATCH(v_bd_epg0);
    route_domain v_rd(100);
    WAIT_FOR_MATCH(v_rd);
    interface v_phy("opflex-itf",
                    interface::type_t::AFPACKET,
                    interface::admin_state_t::UP);
    sub_interface v_upl_epg0(v_phy, interface::admin_state_t::UP, 0xA0A);
    WAIT_FOR_MATCH(v_upl_epg0);
    WAIT_FOR_MATCH(l2_binding(v_upl_epg0, v_bd_epg0));

    interface *v_bvi_epg0 = new interface(
        "bvi-100", interface::type_t::BVI, interface::admin_state_t::UP, v_rd);
    v_bvi_epg0->set(vMac);
    WAIT_FOR_MATCH(*v_bvi_epg0);

    gbp_bridge_domain *v_gbd0 = new gbp_bridge_domain(v_bd_epg0, *v_bvi_epg0);
    WAIT_FOR_MATCH(*v_gbd0);

    gbp_endpoint_group *v_epg0 =
        new gbp_endpoint_group(0xA0A, v_upl_epg0, v_rd, *v_gbd0);
    WAIT_FOR_MATCH(*v_epg0);

    /*
     * Find the EP's interface
     */
    interface *v_itf_ep0 = new interface("port80",
                                         interface::type_t::AFPACKET,
                                         interface::admin_state_t::UP,
                                         v_rd);
    WAIT_FOR_MATCH(*v_itf_ep0);

    /*
     * the Endpoint
     */
    WAIT_FOR_MATCH(gbp_endpoint(*v_itf_ep0, getEPIps(ep0), v_mac_ep0, *v_epg0));

    /*
     * An Another EP in another EPG
     */
    vppManager.egDomainUpdated(epg1->getURI());
    vppManager.endpointUpdated(ep2->getUUID());

    bridge_domain v_bd_epg1(101, bridge_domain::learning_mode_t::OFF);
    WAIT_FOR_MATCH(v_bd_epg1);

    interface *v_itf_ep2 = new interface("port11",
                                         interface::type_t::AFPACKET,
                                         interface::admin_state_t::UP,
                                         v_rd);
    WAIT_FOR_MATCH(*v_itf_ep2);
    interface *v_bvi_epg1 = new interface(
        "bvi-101", interface::type_t::BVI, interface::admin_state_t::UP, v_rd);
    v_bvi_epg1->set(vMac);
    WAIT_FOR_MATCH(*v_bvi_epg1);
    sub_interface v_upl_epg1(v_phy, interface::admin_state_t::UP, 0xA0B);
    WAIT_FOR_MATCH(v_upl_epg1);

    gbp_bridge_domain *v_gbd1 = new gbp_bridge_domain(v_bd_epg1, *v_bvi_epg1);
    WAIT_FOR_MATCH(*v_gbd1);
    gbp_endpoint_group *v_epg1 =
        new gbp_endpoint_group(0xA0B, v_upl_epg1, v_rd, *v_gbd1);
    WAIT_FOR_MATCH(*v_epg1);

    WAIT_FOR_MATCH(gbp_endpoint(*v_itf_ep2, getEPIps(ep2), v_mac_ep2, *v_epg1));

    /*
     * remove EP0
     */
    epSrc.removeEndpoint(ep0->getUUID());
    vppManager.endpointUpdated(ep0->getUUID());

    for (auto &ipAddr : getEPIps(ep0))
    {
        WAIT_FOR_NOT_PRESENT(
            bridge_domain_arp_entry(v_bd_epg0, ipAddr, v_mac_ep0));
        WAIT_FOR_NOT_PRESENT(neighbour(*v_bvi_epg0, ipAddr, v_mac_ep0));
        WAIT_FOR_NOT_PRESENT(
            route::ip_route(v_rd, {ipAddr}, {ipAddr, *v_bvi_epg0}));
    }
    WAIT_FOR_NOT_PRESENT(bridge_domain_entry(v_bd_epg0, v_mac_ep0, *v_itf_ep0));
    WAIT_FOR_NOT_PRESENT(l2_binding(*v_itf_ep0, v_bd_epg0));
    WAIT_FOR_NOT_PRESENT(*v_itf_ep0);
    delete v_itf_ep0;

    /*
     * should still have state from EP2
     */
    WAIT_FOR_MATCH(gbp_endpoint(*v_itf_ep2, getEPIps(ep2), v_mac_ep2, *v_epg1));

    /*
     * remove the rest of the state
     */
    epSrc.removeEndpoint(ep2->getUUID());
    vppManager.endpointUpdated(ep2->getUUID());
    removeEpg(epg0);
    vppManager.egDomainUpdated(epg0->getURI());

    /*
     * An Another EP in another EPG - trunk port
     */
    vppManager.egDomainUpdated(epg1->getURI());
    vppManager.endpointUpdated(ep4->getUUID());

    WAIT_FOR_MATCH(v_bd_epg1);

    interface *v_itf_ep4 = new interface(
        "port40", interface::type_t::AFPACKET, interface::admin_state_t::UP);
    WAIT_FOR_MATCH(*v_itf_ep4);
    interface *v_trunk_itf_ep4 =
        new sub_interface(*v_itf_ep4, interface::admin_state_t::UP, v_rd, 1000);
    WAIT_FOR_MATCH(*v_trunk_itf_ep4);
    WAIT_FOR_MATCH(*v_bvi_epg1);
    WAIT_FOR_MATCH(v_upl_epg1);
    WAIT_FOR_MATCH(*v_epg1);

    WAIT_FOR_MATCH(
        gbp_endpoint(*v_trunk_itf_ep4, getEPIps(ep4), v_mac_ep4, *v_epg1));

    epSrc.removeEndpoint(ep4->getUUID());
    vppManager.endpointUpdated(ep4->getUUID());

    delete v_itf_ep2;
    delete v_trunk_itf_ep4;
    delete v_itf_ep4;

    removeEpg(epg1);
    vppManager.egDomainUpdated(epg1->getURI());

    /*
     * withdraw the route domain.
     */
    opflex::modb::Mutator m1(framework, policyOwner);
    rd0->remove();
    m1.commit();

    vppManager.domainUpdated(modelgbp::gbp::RoutingDomain::CLASS_ID,
                             rd0->getURI());

    WAIT_FOR_NOT_PRESENT(*v_epg0);
    delete v_epg0;
    WAIT_FOR_NOT_PRESENT(*v_epg1);
    delete v_epg1;

    WAIT_FOR_NOT_PRESENT(*v_gbd0);
    delete v_gbd0;
    WAIT_FOR_NOT_PRESENT(*v_gbd1);
    delete v_gbd1;

    WAIT_FOR_NOT_PRESENT(l2_binding(v_upl_epg0, v_bd_epg0));
    WAIT_FOR_NOT_PRESENT(l2_binding(*v_bvi_epg0, v_bd_epg0));
    WAIT_FOR_NOT_PRESENT(*v_bvi_epg0);
    delete v_bvi_epg0;

    WAIT_FOR_NOT_PRESENT(l2_binding(v_upl_epg1, v_bd_epg1));
    WAIT_FOR_NOT_PRESENT(l2_binding(*v_bvi_epg1, v_bd_epg1));
    WAIT_FOR_NOT_PRESENT(*v_bvi_epg1);
    delete v_bvi_epg1;

    /*
     * if the RD has gone then so have all the rest of the routes.
     */
    WAIT_FOR_NOT_PRESENT(v_bd_epg0);
    WAIT_FOR_NOT_PRESENT(v_bd_epg1);
    WAIT_FOR_NOT_PRESENT(v_rd);
}

BOOST_FIXTURE_TEST_CASE(endpoint_nat_add_del, VppStitchedManagerFixture)
{
    createNatObjects();
    assignEpg0ToFd0();

    vppManager.egDomainUpdated(epg0->getURI());
    vppManager.egDomainUpdated(epg1->getURI());
    vppManager.egDomainUpdated(epg_nat->getURI());
    vppManager.domainUpdated(modelgbp::gbp::RoutingDomain::CLASS_ID,
                             rd0->getURI());
    vppManager.domainUpdated(modelgbp::gbp::RoutingDomain::CLASS_ID,
                             rd_ext->getURI());
    vppManager.endpointUpdated(ep0->getUUID());
    vppManager.endpointUpdated(ep2->getUUID());

    /*
     * Global state
     */
    interface v_phy("opflex-itf",
                    interface::type_t::AFPACKET,
                    interface::admin_state_t::UP);
    route_domain v_rd(100);
    WAIT_FOR_MATCH(v_rd);
    route_domain v_rd_nat(101);
    WAIT_FOR_MATCH(v_rd_nat);
    mac_address_t v_mac_ep0("00:00:00:00:80:00");

    address a5_5_5_5 = address::from_string("5.5.5.5");

    /*
     * some of the state expected for EPG0, EPG1 and EPG_NAT
     */
    sub_interface v_upl_epg0(v_phy, interface::admin_state_t::UP, 0xA0A);
    WAIT_FOR_MATCH(v_upl_epg0);
    bridge_domain v_bd_epg0(100, bridge_domain::learning_mode_t::OFF);
    WAIT_FOR_MATCH(v_bd_epg0);
    interface *v_bvi_epg0 = new interface(
        "bvi-100", interface::type_t::BVI, interface::admin_state_t::UP, v_rd);
    v_bvi_epg0->set(vMac);
    WAIT_FOR_MATCH(*v_bvi_epg0);
    gbp_bridge_domain *v_gbd0 = new gbp_bridge_domain(v_bd_epg0, *v_bvi_epg0);
    WAIT_FOR_MATCH(*v_gbd0);
    gbp_endpoint_group *v_epg0 =
        new gbp_endpoint_group(0xA0A, v_upl_epg0, v_rd, *v_gbd0);
    WAIT_FOR_MATCH(*v_epg0);

    sub_interface v_upl_epg1(v_phy, interface::admin_state_t::UP, 0xA0B);
    WAIT_FOR_MATCH(v_upl_epg1);
    bridge_domain v_bd_epg1(101, bridge_domain::learning_mode_t::OFF);
    WAIT_FOR_MATCH(v_bd_epg1);
    interface *v_bvi_epg1 = new interface(
        "bvi-101", interface::type_t::BVI, interface::admin_state_t::UP, v_rd);
    v_bvi_epg1->set(vMac);
    WAIT_FOR_MATCH(*v_bvi_epg1);
    gbp_bridge_domain *v_gbd1 = new gbp_bridge_domain(v_bd_epg1, *v_bvi_epg1);
    WAIT_FOR_MATCH(*v_gbd1);
    gbp_endpoint_group *v_epg1 =
        new gbp_endpoint_group(0xA0B, v_upl_epg1, v_rd, *v_gbd1);
    WAIT_FOR_MATCH(*v_epg1);

    bridge_domain v_bd_epg_nat(102, bridge_domain::learning_mode_t::OFF);
    WAIT_FOR_MATCH(v_bd_epg_nat);
    sub_interface v_upl_epg_nat(v_phy, interface::admin_state_t::UP, 0x424);
    WAIT_FOR_MATCH(v_upl_epg_nat);

    interface *v_bvi_nat = new interface("bvi-102",
                                         interface::type_t::BVI,
                                         interface::admin_state_t::UP,
                                         v_rd_nat);
    v_bvi_nat->set(vMac);

    WAIT_FOR_MATCH(*v_bvi_nat);
    gbp_bridge_domain *v_gbd_nat =
        new gbp_bridge_domain(v_bd_epg_nat, *v_bvi_nat);
    WAIT_FOR_MATCH(*v_gbd_nat);
    gbp_endpoint_group *v_epg_nat =
        new gbp_endpoint_group(0x424, v_upl_epg_nat, v_rd_nat, *v_gbd_nat);
    WAIT_FOR_MATCH(*v_epg_nat);
    interface *v_bvi_epg_nat = new interface("bvi-102",
                                             interface::type_t::BVI,
                                             interface::admin_state_t::UP,
                                             v_rd_nat);
    v_bvi_epg_nat->set(vMac);
    WAIT_FOR_MATCH(*v_bvi_epg_nat);

    /*
     * The existence of the floating IPs mean there is a static
     * mapping and a NAT inside binding on the EPG's BVI
     */
    interface *v_itf_ep0 = new interface("port80",
                                         interface::type_t::AFPACKET,
                                         interface::admin_state_t::UP,
                                         v_rd);
    WAIT_FOR_MATCH(*v_itf_ep0);

    WAIT_FOR_MATCH(nat_binding(*v_bvi_epg0,
                               direction_t::INPUT,
                               l3_proto_t::IPV4,
                               nat_binding::zone_t::INSIDE));
    WAIT_FOR_MATCH(nat_binding(*v_bvi_epg0,
                               direction_t::INPUT,
                               l3_proto_t::IPV6,
                               nat_binding::zone_t::INSIDE));
    WAIT_FOR_MATCH(nat_binding(*v_bvi_epg1,
                               direction_t::INPUT,
                               l3_proto_t::IPV4,
                               nat_binding::zone_t::INSIDE));
    WAIT_FOR_MATCH(nat_binding(*v_bvi_epg1,
                               direction_t::INPUT,
                               l3_proto_t::IPV6,
                               nat_binding::zone_t::INSIDE));
    interface v_recirc_itf("recirc-" + std::to_string(0xA0A),
                           interface::type_t::LOOPBACK,
                           interface::admin_state_t::UP,
                           v_rd);
    WAIT_FOR_MATCH(v_recirc_itf);

    WAIT_FOR_MATCH(l2_binding(v_recirc_itf, v_bd_epg0));

    WAIT_FOR_MATCH(nat_binding(v_recirc_itf,
                               direction_t::INPUT,
                               l3_proto_t::IPV4,
                               nat_binding::zone_t::OUTSIDE));

    WAIT_FOR_MATCH(nat_binding(v_recirc_itf,
                               direction_t::INPUT,
                               l3_proto_t::IPV6,
                               nat_binding::zone_t::OUTSIDE));

    WAIT_FOR_MATCH(gbp_recirc(v_recirc_itf,
                              gbp_recirc::type_t::INTERNAL,
                              *v_epg0));

    /*
     * floating IP state in the NAT BD/RD
     */
    WAIT_FOR_MATCH(
        nat_static(v_rd, address::from_string("10.20.44.2"), a5_5_5_5));
    WAIT_FOR_MATCH(bridge_domain_arp_entry(v_bd_epg_nat, a5_5_5_5, v_mac_ep0));
    WAIT_FOR_MATCH(bridge_domain_entry(v_bd_epg_nat, v_mac_ep0, v_recirc_itf));
    WAIT_FOR_MATCH(neighbour(*v_bvi_epg_nat, a5_5_5_5, v_mac_ep0));
    /* in the NAT RD the floating IP routes via the EPG's recirc */
    WAIT_FOR_MATCH(route::ip_route(
        v_rd_nat,
        a5_5_5_5,
        {v_recirc_itf, nh_proto_t::IPV4, route::path::flags_t::DVR}));

    /*
     * At this point the external subnet is not via NAT so it's an
     * GBP internal subnet via the uplink
     */
    WAIT_FOR_MATCH(gbp_subnet(v_rd,
                              {address::from_string("5.5.0.0"), 16},
                              gbp_subnet::type_t::STITCHED_INTERNAL));
    WAIT_FOR_MATCH(gbp_subnet(v_rd_nat,
                              {address::from_string("5.5.5.0"), 24},
                              gbp_subnet::type_t::STITCHED_INTERNAL));

    /*
     * modify the external subnet so that it is now NAT'd
     */
    {
        opflex::modb::Mutator mutator(framework, policyOwner);
        l3ext_net->addGbpL3ExternalNetworkToNatEPGroupRSrc()->setTargetEpGroup(
            epg_nat->getURI());
        mutator.commit();

        WAIT_FOR(policyMgr.getVnidForGroup(epg_nat->getURI()).get_value_or(0) ==
                     0x424,
                 500);
    }
    vppManager.domainUpdated(modelgbp::gbp::RoutingDomain::CLASS_ID,
                             rd0->getURI());

    /*
     * A recirc interface into the NAT EPG
     */
    interface v_nat_recirc_itf("recirc-" + std::to_string(0x424),
                               interface::type_t::LOOPBACK,
                               interface::admin_state_t::UP,
                               v_rd_nat);
    WAIT_FOR_MATCH(v_nat_recirc_itf);

    WAIT_FOR_MATCH(l2_binding(v_nat_recirc_itf, v_bd_epg_nat));

    WAIT_FOR_MATCH(nat_binding(v_nat_recirc_itf,
                               direction_t::INPUT,
                               l3_proto_t::IPV4,
                               nat_binding::zone_t::OUTSIDE));

    WAIT_FOR_MATCH(nat_binding(v_nat_recirc_itf,
                               direction_t::INPUT,
                               l3_proto_t::IPV6,
                               nat_binding::zone_t::OUTSIDE));

    gbp_recirc *v_nat_grecirc = new gbp_recirc(v_nat_recirc_itf,
                                               gbp_recirc::type_t::EXTERNAL,
                                               *v_epg_nat);

    /*
     * with the RD the route becomes external via the recirc
     */
    WAIT_FOR_MATCH(gbp_subnet(v_rd,
                              {address::from_string("5.5.0.0"), 16},
                              *v_nat_grecirc,
                              *v_epg_nat));
    WAIT_FOR_MATCH(gbp_subnet(v_rd_nat,
                              {address::from_string("5.5.5.0"), 24},
                              gbp_subnet::type_t::STITCHED_INTERNAL));

    /*
     * modify the external subnet so that it is no longer NAT'd
     */
    {
        opflex::modb::Mutator mutator(framework, policyOwner);
        l3ext_net->addGbpL3ExternalNetworkToNatEPGroupRSrc()->unsetTarget();
        mutator.commit();

        WAIT_FOR(policyMgr.getVnidForGroup(epg_nat->getURI()).get_value_or(0) ==
                     0x424,
                 500);
    }
    vppManager.domainUpdated(modelgbp::gbp::RoutingDomain::CLASS_ID,
                             rd0->getURI());

    /*
     * subnet goes back to internal and the recircs are gone.
     */
    WAIT_FOR_MATCH(gbp_subnet(v_rd,
                              {address::from_string("5.5.0.0"), 16},
                              gbp_subnet::type_t::STITCHED_INTERNAL));
    WAIT_FOR_MATCH(gbp_subnet(v_rd_nat,
                              {address::from_string("5.5.5.0"), 24},
                              gbp_subnet::type_t::STITCHED_INTERNAL));
    WAIT_FOR_NOT_PRESENT(*v_nat_grecirc);
    delete v_nat_grecirc;

    /*
     * withdraw the Floating IP
     */
    ep0->clearIPAddressMappings();
    epSrc.updateEndpoint(*ep0);
    vppManager.endpointUpdated(ep0->getUUID());

    WAIT_FOR_NOT_PRESENT(
        nat_static(v_rd, address::from_string("10.20.44.2"), a5_5_5_5));

    /* cleanup */
    opflex::modb::Mutator m1(framework, policyOwner);
    rd0->remove();
    rd_ext->remove();
    m1.commit();
    vppManager.domainUpdated(modelgbp::gbp::RoutingDomain::CLASS_ID,
                             rd0->getURI());
    vppManager.domainUpdated(modelgbp::gbp::RoutingDomain::CLASS_ID,
                             rd_ext->getURI());

    epSrc.removeEndpoint(ep0->getUUID());
    epSrc.removeEndpoint(ep2->getUUID());
    vppManager.endpointUpdated(ep0->getUUID());
    vppManager.endpointUpdated(ep2->getUUID());

    removeEpg(epg0);
    vppManager.egDomainUpdated(epg0->getURI());
    removeEpg(epg1);
    vppManager.egDomainUpdated(epg1->getURI());
    removeEpg(epg_nat);
    vppManager.egDomainUpdated(epg_nat->getURI());

    WAIT_FOR_NOT_PRESENT(nat_binding(*v_bvi_epg0,
                                     direction_t::INPUT,
                                     l3_proto_t::IPV6,
                                     nat_binding::zone_t::INSIDE));

    WAIT_FOR_NOT_PRESENT(*v_epg_nat);
    delete v_epg_nat;
    WAIT_FOR_NOT_PRESENT(*v_gbd_nat);
    delete v_gbd_nat;

    WAIT_FOR_NOT_PRESENT(*v_epg0);
    WAIT_FOR_NOT_PRESENT(*v_epg1);
    delete v_epg0;
    delete v_epg1;

    WAIT_FOR_NOT_PRESENT(*v_gbd0);
    WAIT_FOR_NOT_PRESENT(*v_gbd1);
    delete v_gbd0;
    delete v_gbd1;

    WAIT_FOR_NOT_PRESENT(*v_bvi_nat);
    WAIT_FOR_NOT_PRESENT(*v_bvi_epg0);
    WAIT_FOR_NOT_PRESENT(*v_bvi_epg1);
}

BOOST_FIXTURE_TEST_CASE(trans_endpoint_group_add_del,
                        VppTransportManagerFixture)
{
    address_v4 spine_mac, spine_v4, spine_v6, bd_mc;
    address host, router;

    host = boost::asio::ip::address::from_string("192.168.1.1");
    router = boost::asio::ip::address::from_string("192.168.1.2");

    route::prefix_t pfx(host, 24);
    mac_address_t mac("00:00:11:22:33:44");

    framework.getMacProxy(spine_mac);
    framework.getV4Proxy(spine_v4);
    framework.getV6Proxy(spine_v6);

    bd_mc = boost::asio::ip::address_v4::from_string("224.1.1.1");
    do_dhcp();

    /*
     * boot phase so the VPP/host address is learnt
     */
    interface v_phy("opflex-itf",
                    interface::type_t::AFPACKET,
                    interface::admin_state_t::UP);
    sub_interface v_sub(v_phy, interface::admin_state_t::UP, 4093);

    WAIT_FOR_MATCH(v_phy);
    WAIT_FOR_MATCH(v_sub);

    /*
     * create an endpoint group
     */
    vppManager.egDomainUpdated(epg0->getURI());

    /*
     * Check for a bridge domain 100
     */
    bridge_domain v_bd(100, bridge_domain::learning_mode_t::OFF);
    WAIT_FOR_MATCH(v_bd);

    /*
     * check for the presence of a VOM route-domain matching the EPG's
     * ID's are offset by 100.
     */
    route_domain v_rd(100);
    WAIT_FOR_MATCH(v_rd);

    interface *v_bvi = new interface(
        "bvi-100", interface::type_t::BVI, interface::admin_state_t::UP, v_rd);
    v_bvi->set(vMac);

    WAIT_FOR_MATCH(*v_bvi);

    /*
     * the interfaces to the spine proxy.
     *   for the BD with VNI=0xAA and the RD VNI=0xBB
     */
    vxlan_tunnel *vt_mac =
        new vxlan_tunnel(host, spine_mac, 0xAA, vxlan_tunnel::mode_t::GBP);
    WAIT_FOR_MATCH(*vt_mac);
    vxlan_tunnel *vt_mc =
        new vxlan_tunnel(host, bd_mc, 0xAA, vxlan_tunnel::mode_t::GBP);
    WAIT_FOR_MATCH(*vt_mc);
    vxlan_tunnel *vt_v4 =
        new vxlan_tunnel(host, spine_v4, 0xBB, vxlan_tunnel::mode_t::GBP);
    WAIT_FOR_MATCH(*vt_v4);
    vxlan_tunnel *vt_v6 =
        new vxlan_tunnel(host, spine_v6, 0xBB, vxlan_tunnel::mode_t::GBP);
    WAIT_FOR_MATCH(*vt_v6);

    gbp_bridge_domain *v_gbd = new gbp_bridge_domain(v_bd, *v_bvi, *vt_mac, *vt_mc);
    WAIT_FOR_MATCH(*v_gbd);
    gbp_route_domain *v_grd = new gbp_route_domain(v_rd, *vt_v4, *vt_v6);
    WAIT_FOR_MATCH(*v_grd);

    gbp_endpoint_group *v_epg = new gbp_endpoint_group(0xA0A, 0xBA, *v_grd, *v_gbd);
    WAIT_FOR_MATCH(*v_epg);

    inspector.handle_input("all", std::cout);

    WAIT_FOR_MATCH(gbp_vxlan(0xAA, *v_gbd));
    WAIT_FOR_MATCH(gbp_vxlan(0xBB, *v_grd));

    /*
     * mcast vxlan tunnels bound to BD
     */
    boost::asio::ip::address bd_mcast =
        boost::asio::ip::address::from_string("224.1.1.1");

    vxlan_tunnel vt_bd_mcast(
        host, bd_mcast, 0xAA, v_sub, vxlan_tunnel::mode_t::GBP);
    WAIT_FOR_MATCH(vt_bd_mcast);
    WAIT_FOR_MATCH(l2_binding(vt_bd_mcast, v_bd));

    igmp_binding igmp_b(v_sub);
    WAIT_FOR_MATCH(igmp_b);
    WAIT_FOR_MATCH(igmp_listen(igmp_b, bd_mcast.to_v4()));

    removeEpg(epg0);
    vppManager.egDomainUpdated(epg0->getURI());

    WAIT_FOR_NOT_PRESENT(*v_epg);
    delete v_epg;

    WAIT_FOR_NOT_PRESENT(*v_gbd);
    WAIT_FOR_NOT_PRESENT(*v_grd);
    delete v_gbd;
    delete v_grd;

    WAIT_FOR_NOT_PRESENT(*v_bvi);
    WAIT_FOR_NOT_PRESENT(*vt_mac);
    WAIT_FOR_NOT_PRESENT(*vt_v4);
    WAIT_FOR_NOT_PRESENT(*vt_v6);
    delete vt_mac;
    delete vt_v4;
    delete vt_v6;
    delete v_bvi;
}

BOOST_FIXTURE_TEST_CASE(ext_itf, VppTransportManagerFixture)
{
    do_dhcp();
    vppManager.externalInterfaceUpdated(ext_itf0->getURI());

    interface v_phy("opflex-itf",
                    interface::type_t::AFPACKET,
                    interface::admin_state_t::UP);
    sub_interface v_sub(v_phy, interface::admin_state_t::UP, 4093);

    WAIT_FOR_MATCH(v_phy);
    WAIT_FOR_MATCH(v_sub);

    route_domain v_rd(100);
    WAIT_FOR_MATCH(v_rd);

    bridge_domain v_bd(100, bridge_domain::learning_mode_t::OFF);
    WAIT_FOR_MATCH(v_bd);

    std::shared_ptr<interface> v_bvi =
      std::make_shared<interface>("bvi-100",
                                  interface::type_t::BVI,
                                  interface::admin_state_t::UP,
                                  v_rd);
    l2_address_t l2addr(mac_address_t("00:00:00:00:80:00"));
    v_bvi->set(l2addr);

    WAIT_FOR_MATCH(*v_bvi);

    boost::asio::ip::address bd_mcast =
      boost::asio::ip::address::from_string("224.1.2.2");

    std::shared_ptr<vxlan_tunnel> vt_bd_mcast =
      std::make_shared<vxlan_tunnel>(host, bd_mcast, 1133, v_sub,
                                     vxlan_tunnel::mode_t::GBP);
    WAIT_FOR_MATCH(*vt_bd_mcast);
    igmp_binding igmp_b(v_sub);
    WAIT_FOR_MATCH(igmp_b);
    WAIT_FOR_MATCH(igmp_listen(igmp_b, bd_mcast.to_v4()));

    gbp_bridge_domain *v_gbd =
      new gbp_bridge_domain(v_bd, v_bvi, {}, vt_bd_mcast);
    WAIT_FOR_MATCH(*v_gbd);
    gbp_route_domain *v_grd = new gbp_route_domain(v_rd);
    WAIT_FOR_MATCH(*v_grd);

    /* 0x80000064 is the internally generated EPG-ID */
    gbp_endpoint_group *v_epg0 =
      new gbp_endpoint_group(0x80000065, 1234, *v_grd, *v_gbd);
    WAIT_FOR_MATCH(*v_epg0);
    gbp_endpoint_group *v_epg1 =
      new gbp_endpoint_group(0x80000064, 1235, *v_grd, *v_gbd);
    WAIT_FOR_MATCH(*v_epg1);

    gbp_ext_itf *v_ei = new gbp_ext_itf(*v_bvi, *v_gbd, *v_grd);
    WAIT_FOR_MATCH(*v_ei);

    WAIT_FOR_MATCH(gbp_subnet(v_rd, {"105.0.0.0", 24}, *v_epg0));
    WAIT_FOR_MATCH(gbp_subnet(v_rd, {"106.0.0.0", 24}, *v_epg0));
    WAIT_FOR_MATCH(gbp_subnet(v_rd, {"107.0.0.0", 24}, *v_epg1));
    WAIT_FOR_MATCH(gbp_subnet(v_rd, {"108.0.0.0", 24}, *v_epg1));

    {
      opflex::modb::Mutator m2(framework, policyOwner);
      ext_itf0->remove();
      m2.commit();
    }
    vppManager.externalInterfaceUpdated(ext_itf0->getURI());

    WAIT_FOR_NOT_PRESENT(gbp_subnet(v_rd, {"108.0.0.0", 24}, *v_epg1));
    WAIT_FOR_NOT_PRESENT(*v_ei);
    delete v_ei;

    WAIT_FOR_NOT_PRESENT(*v_epg0);
    WAIT_FOR_NOT_PRESENT(*v_epg1);
    delete v_epg0;
    delete v_epg1;

    WAIT_FOR_NOT_PRESENT(*v_grd);
    WAIT_FOR_NOT_PRESENT(*v_gbd);
}

BOOST_FIXTURE_TEST_CASE(static_route, VppTransportManagerFixture)
{
    vppManager.staticRouteUpdated(static_route1->getURI());

    route_domain v_rd(100);
    WAIT_FOR_MATCH(v_rd);

    route::prefix_t pfx(boost::asio::ip::address::from_string("101.101.0.0"), 16);

    boost::asio::ip::address nh1, nh2, nh3;
    nh1 = boost::asio::ip::address::from_string("100.100.100.2");
    nh2 = boost::asio::ip::address::from_string("100.100.100.3");
    nh3 = boost::asio::ip::address::from_string("100.100.100.4");

    route::ip_route v_route(v_rd, pfx);
    v_route.add({v_rd, nh1});
    v_route.add({v_rd, nh2});
    v_route.add({v_rd, nh3});

    WAIT_FOR_MATCH(v_route);

    opflex::modb::Mutator m1(framework, policyOwner);
    static_route1->remove();
    m1.commit();
    vppManager.staticRouteUpdated(static_route1->getURI());

    WAIT_FOR_NOT_PRESENT(v_route);
}

BOOST_FIXTURE_TEST_CASE(secGroup, VppStitchedManagerFixture)
{
    using modelgbp::gbpe::L24Classifier;
    using namespace modelgbp::gbp;
    createObjects();
    createPolicyObjects();

    PolicyManager::rule_list_t lrules;
    vppManager.egDomainUpdated(epg0->getURI());
    vppManager.endpointUpdated(ep0->getUUID());

    std::shared_ptr<SecGroup> secGrp1, secGrp2;
    {
        opflex::modb::Mutator mutator(framework, policyOwner);
        secGrp1 = space->addGbpSecGroup("secgrp1");
        secGrp1->addGbpSecGroupSubject("1_subject1")
            ->addGbpSecGroupRule("1_1_rule1")
            ->setDirection(DirectionEnumT::CONST_IN)
            .setOrder(100)
            .addGbpRuleToClassifierRSrc(classifier1->getURI().toString());
        secGrp1->addGbpSecGroupSubject("1_subject1")
            ->addGbpSecGroupRule("1_1_rule2")
            ->setDirection(DirectionEnumT::CONST_IN)
            .setOrder(150)
            .addGbpRuleToClassifierRSrc(classifier8->getURI().toString());
        secGrp1->addGbpSecGroupSubject("1_subject1")
            ->addGbpSecGroupRule("1_1_rule3")
            ->setDirection(DirectionEnumT::CONST_IN)
            .setOrder(200)
            .addGbpRuleToClassifierRSrc(classifier6->getURI().toString());
        secGrp1->addGbpSecGroupSubject("1_subject1")
            ->addGbpSecGroupRule("1_1_rule4")
            ->setDirection(DirectionEnumT::CONST_IN)
            .setOrder(300)
            .addGbpRuleToClassifierRSrc(classifier7->getURI().toString());
        mutator.commit();
    }

    ep0->addSecurityGroup(secGrp1->getURI());
    epSrc.updateEndpoint(*ep0);

    WAIT_FOR_DO(lrules.size() == 4, 500, lrules.clear();
                policyMgr.getSecGroupRules(secGrp1->getURI(), lrules));

    vppManager.endpointUpdated(ep0->getUUID());

    route_domain v_rd(100);
    WAIT_FOR1(is_match(v_rd));

    /*
     * Find the EP's interface
     */
    interface *v_itf = new interface("port80",
                                     interface::type_t::AFPACKET,
                                     interface::admin_state_t::UP,
                                     v_rd);
    WAIT_FOR1(is_match(*v_itf));

    ACL::ethertype_rule_t e1(ethertype_t::IPV4, direction_t::OUTPUT);
    ACL::ethertype_rule_t e2(ethertype_t::IPV6, direction_t::OUTPUT);
    ACL::ethertype_rule_t e3(ethertype_t::IPV4, direction_t::OUTPUT);
    ACL::ethertype_rule_t e4(ethertype_t::IPV4, direction_t::OUTPUT);

    ACL::acl_ethertype::ethertype_rules_t e_rules = {e1, e2, e3, e4};

    WAIT_FOR1(is_match(ACL::acl_ethertype(*v_itf, e_rules)));

    ACL::action_t act = ACL::action_t::PERMIT;
    ACL::l3_rule rule1(8192,
                       act,
                       route::prefix_t::ZERO,
                       route::prefix_t::ZERO,
                       6,
                       0,
                       65535,
                       80,
                       65535,
                       0,
                       0);
    ACL::l3_rule rule2(8064,
                       act,
                       route::prefix_t::ZEROv6,
                       route::prefix_t::ZEROv6,
                       6,
                       0,
                       65535,
                       80,
                       65535,
                       0,
                       0);
    ACL::l3_rule rule3(7808,
                       act,
                       route::prefix_t::ZERO,
                       route::prefix_t::ZERO,
                       6,
                       22,
                       65535,
                       0,
                       65535,
                       3,
                       3);
    ACL::l3_rule rule4(7680,
                       act,
                       route::prefix_t::ZERO,
                       route::prefix_t::ZERO,
                       6,
                       21,
                       65535,
                       0,
                       65535,
                       16,
                       16);
    ACL::l3_list::rules_t rules({rule1, rule2, rule3, rule4});

    boost::hash<std::string> string_hash;
    const std::string secGrpKey =
        std::to_string(string_hash("/PolicyUniverse/PolicySpace/"
                                   "tenant0/GbpSecGroup/secgrp1/"));

    WAIT_FOR1(is_match(ACL::l3_list(secGrpKey + "-out", rules)));

    {
        opflex::modb::Mutator mutator(framework, policyOwner);
        secGrp2 = space->addGbpSecGroup("secgrp2");
        secGrp2->addGbpSecGroupSubject("2_subject1")
            ->addGbpSecGroupRule("2_1_rule1")
            ->addGbpRuleToClassifierRSrc(classifier0->getURI().toString());
        secGrp2->addGbpSecGroupSubject("2_subject1")
            ->addGbpSecGroupRule("2_1_rule2")
            ->setDirection(DirectionEnumT::CONST_BIDIRECTIONAL)
            .setOrder(20)
            .addGbpRuleToClassifierRSrc(classifier5->getURI().toString());
        secGrp2->addGbpSecGroupSubject("2_subject1")
            ->addGbpSecGroupRule("2_1_rule3")
            ->setDirection(DirectionEnumT::CONST_OUT)
            .setOrder(30)
            .addGbpRuleToClassifierRSrc(classifier9->getURI().toString());
        mutator.commit();
    }

    ep0->addSecurityGroup(secGrp2->getURI());
    epSrc.updateEndpoint(*ep0);

    lrules.clear();
    WAIT_FOR_DO(lrules.size() == 2, 500, lrules.clear();
                policyMgr.getSecGroupRules(secGrp2->getURI(), lrules));

    vppManager.endpointUpdated(ep0->getUUID());

    ACL::ethertype_rule_t e6(ethertype_t::FCOE, direction_t::OUTPUT);
    ACL::ethertype_rule_t e7(ethertype_t::FCOE, direction_t::INPUT);
    ACL::ethertype_rule_t e8(ethertype_t::IPV4, direction_t::INPUT);

    ACL::acl_ethertype::ethertype_rules_t e_rules2 = {
        e1, e2, e3, e4, e6, e7, e8};

    WAIT_FOR_MATCH(ACL::acl_ethertype(*v_itf, e_rules2));

    act = ACL::action_t::PERMITANDREFLEX;
    ACL::l3_rule rule5(8064,
                       act,
                       route::prefix_t::ZERO,
                       route::prefix_t::ZERO,
                       6,
                       0,
                       65535,
                       22,
                       65535,
                       0,
                       0);
    ACL::l3_list::rules_t rules2({rule5});

    const std::string secGrpKey2 = std::to_string(
        string_hash("/PolicyUniverse/PolicySpace/"
                    "tenant0/GbpSecGroup/secgrp1/,/PolicyUniverse/"
                    "PolicySpace/tenant0/GbpSecGroup/secgrp2/"));

    WAIT_FOR1(is_match(ACL::l3_list(secGrpKey2 + "-in", rules2)));

    delete v_itf;
}

BOOST_FIXTURE_TEST_CASE(policy, VppStitchedManagerFixture)
{
    createObjects();
    createPolicyObjects();
    PolicyManager::uri_set_t egs;
    WAIT_FOR_DO(egs.size() == 2, 1000, egs.clear();
                policyMgr.getContractProviders(con1->getURI(), egs));
    egs.clear();
    WAIT_FOR_DO(egs.size() == 2, 500, egs.clear();
                policyMgr.getContractConsumers(con1->getURI(), egs));
    egs.clear();

    WAIT_FOR_DO(egs.size() == 2, 500, egs.clear();
                policyMgr.getContractIntra(con2->getURI(), egs));

    /* add con2 */
    vppManager.contractUpdated(con2->getURI());

    ACL::action_t act = ACL::action_t::PERMIT;
    ACL::l3_rule rule1(8192,
                       act,
                       route::prefix_t::ZERO,
                       route::prefix_t::ZERO,
                       6,
                       0,
                       65535,
                       80,
                       65535,
                       0,
                       0);
    ACL::l3_list::rules_t rules1({rule1});

    gbp_contract::gbp_rules_t grules1 = {{8192, gbp_rule::action_t::PERMIT}};
    gbp_contract::ethertype_set_t allowed1 = {ethertype_t::IPV4,
                                              ethertype_t::FCOE};

    /* add con1 */
    vppManager.contractUpdated(con1->getURI());

    ACL::l3_rule rule2(8192,
                       act,
                       route::prefix_t::ZERO,
                       route::prefix_t::ZERO,
                       6,
                       0,
                       65535,
                       80,
                       65535,
                       0,
                       0);
    ACL::l3_rule rule3(7936,
                       act,
                       route::prefix_t::ZERO,
                       route::prefix_t::ZERO,
                       6,
                       22,
                       65535,
                       0,
                       65535,
                       3,
                       3);
    ACL::l3_rule rule4(7808,
                       act,
                       route::prefix_t::ZERO,
                       route::prefix_t::ZERO,
                       6,
                       21,
                       65535,
                       0,
                       65535,
                       16,
                       16);
    ACL::l3_list::rules_t rules2({rule2, rule3, rule4});

    ACL::l3_list outAcl2(con1->getURI().toString() + "out", rules2);
    WAIT_FOR_MATCH(outAcl2);

    gbp_contract::gbp_rules_t grules2 = {{8192, gbp_rule::action_t::PERMIT},
                                         {7936, gbp_rule::action_t::PERMIT},
                                         {7808, gbp_rule::action_t::PERMIT}};
    gbp_contract::ethertype_set_t allowed2 = {ethertype_t::IPV4,
                                              ethertype_t::ARP};

    WAIT_FOR1(is_match(gbp_contract(3339, 2570, outAcl2, grules2, allowed2)));
    WAIT_FOR1(is_match(gbp_contract(3339, 2571, outAcl2, grules2, allowed2)));
    WAIT_FOR1(is_match(gbp_contract(3338, 2570, outAcl2, grules2, allowed2)));
    WAIT_FOR1(is_match(gbp_contract(3338, 2571, outAcl2, grules2, allowed2)));
}

BOOST_FIXTURE_TEST_CASE(policyPortRange, VppStitchedManagerFixture)
{
    createObjects();
    createPolicyObjects();

    PolicyManager::uri_set_t egs;
    WAIT_FOR_DO(egs.size() == 1, 1000, egs.clear();
                policyMgr.getContractProviders(con3->getURI(), egs));
    egs.clear();
    WAIT_FOR_DO(egs.size() == 1, 500, egs.clear();
                policyMgr.getContractConsumers(con3->getURI(), egs));
    PolicyManager::rule_list_t rules;
    WAIT_FOR_DO(rules.size() == 3, 500, rules.clear();
                policyMgr.getContractRules(con3->getURI(), rules));

    vppManager.contractUpdated(con3->getURI());
    ACL::ethertype_rule_t e1(ethertype_t::IPV4, direction_t::OUTPUT);
    ACL::ethertype_rule_t e2(ethertype_t::IPV4, direction_t::OUTPUT);
    ACL::ethertype_rule_t e3(ethertype_t::IPV4, direction_t::OUTPUT);

    ACL::acl_ethertype::ethertype_rules_t e_rules = {e1, e2, e3};

    ACL::action_t act = ACL::action_t::PERMIT;
    ACL::action_t act1 = ACL::action_t::DENY;
    ACL::l3_rule rule1(8192,
                       act1,
                       route::prefix_t::ZERO,
                       route::prefix_t::ZERO,
                       6,
                       0,
                       65535,
                       80,
                       85,
                       0,
                       0);
    ACL::l3_rule rule2(8064,
                       act,
                       route::prefix_t::ZERO,
                       route::prefix_t::ZERO,
                       6,
                       66,
                       69,
                       94,
                       95,
                       0,
                       0);
    ACL::l3_rule rule3(7936,
                       act,
                       route::prefix_t::ZERO,
                       route::prefix_t::ZERO,
                       1,
                       10,
                       10,
                       5,
                       5,
                       0,
                       0);
    ACL::l3_list::rules_t rules1({rule1, rule2, rule3});

    ACL::l3_list outAcl(con3->getURI().toString() + "out", rules1);
    WAIT_FOR_MATCH(outAcl);
    gbp_contract::gbp_rules_t grules = {{8192, gbp_rule::action_t::PERMIT},
                                        {7936, gbp_rule::action_t::PERMIT},
                                        {7808, gbp_rule::action_t::PERMIT}};

    gbp_contract::ethertype_set_t allowed = {ethertype_t::IPV4,
                                             ethertype_t::ARP};

    WAIT_FOR1(is_match(gbp_contract(2571, 2570, outAcl, grules, allowed)));
}

BOOST_FIXTURE_TEST_CASE(policyRedirect, VppTransportManagerFixture)
{
    using modelgbp::gbpe::L24Classifier;
    using namespace modelgbp;
    using namespace modelgbp::gbp;
    using namespace std;

    createObjects();
    createPolicyObjects();

    shared_ptr<Contract> con5;
    shared_ptr<L24Classifier> classifier11;
    shared_ptr<RedirectAction> action3;
    shared_ptr<RedirectDestGroup> redirDstGrp1;
    shared_ptr<RedirectDestGroup> redirDstGrp2;
    shared_ptr<RedirectDest> redirDst1;
    shared_ptr<RedirectDest> redirDst2;
    shared_ptr<RedirectDest> redirDst3;
    shared_ptr<RedirectDest> redirDst4;
    shared_ptr<RedirectDest> redirDst5;

    opflex::modb::Mutator mutator(framework, policyOwner);
    classifier11 = space->addGbpeL24Classifier("classifier11");
    classifier11->setEtherT(l2::EtherTypeEnumT::CONST_IPV4)
        .setProt(6 /* TCP */)
        .setDFromPort(80);

    redirDstGrp1 = space->addGbpRedirectDestGroup("redirDstGrp1");
    redirDstGrp1->setHashAlgo(HashingAlgorithmEnumT::CONST_SYMMETRIC);
    redirDstGrp1->setResilientHashEnabled(1);
    redirDst1 = redirDstGrp1->addGbpRedirectDest("redirDst1");
    redirDst2 = redirDstGrp1->addGbpRedirectDest("redirDst2");
    opflex::modb::MAC mac1("00:01:02:03:04:05"), mac2("01:02:03:04:05:06");
    redirDst1->setIp("1.1.1.1");
    redirDst1->setMac(mac1);
    redirDst1->addGbpRedirectDestToDomainRSrcBridgeDomain(
        bd0->getURI().toString());
    redirDst1->addGbpRedirectDestToDomainRSrcRoutingDomain(
        rd0->getURI().toString());
    redirDst2->setIp("2.2.2.2");
    redirDst2->setMac(mac2);
    redirDst2->addGbpRedirectDestToDomainRSrcBridgeDomain(
        bd0->getURI().toString());
    redirDst2->addGbpRedirectDestToDomainRSrcRoutingDomain(
        rd0->getURI().toString());
    action3 = space->addGbpRedirectAction("action3");
    action3->addGbpRedirectActionToDestGrpRSrc()->setTargetRedirectDestGroup(
        redirDstGrp1->getURI());
    redirDstGrp2 = space->addGbpRedirectDestGroup("redirDstGrp2");
    redirDst4 = redirDstGrp2->addGbpRedirectDest("redirDst4");
    opflex::modb::MAC mac3("02:03:04:05:06:07"), mac4("03:04:05:06:07:08");
    redirDst4->setIp("4.4.4.4");
    redirDst4->setMac(mac4);
    redirDst4->addGbpRedirectDestToDomainRSrcBridgeDomain(
        bd0->getURI().toString());
    redirDst4->addGbpRedirectDestToDomainRSrcRoutingDomain(
        rd0->getURI().toString());

    con5 = space->addGbpContract("contract5");
    con5->addGbpSubject("5_subject1")
        ->addGbpRule("5_1_rule1")
        ->setDirection(DirectionEnumT::CONST_IN)
        .setOrder(100)
        .addGbpRuleToClassifierRSrc(classifier11->getURI().toString());
    con5->addGbpSubject("5_subject1")
        ->addGbpRule("5_1_rule1")
        ->addGbpRuleToActionRSrcRedirectAction(action3->getURI().toString());

    epg0->addGbpEpGroupToProvContractRSrc(con5->getURI().toString());
    epg1->addGbpEpGroupToConsContractRSrc(con5->getURI().toString());
    mutator.commit();

    PolicyManager::uri_set_t egs;
    WAIT_FOR_DO(egs.size() == 1, 1000, egs.clear();
                policyMgr.getContractProviders(con5->getURI(), egs));
    egs.clear();
    WAIT_FOR_DO(egs.size() == 1, 500, egs.clear();
                policyMgr.getContractConsumers(con5->getURI(), egs));

    vppManager.contractUpdated(con5->getURI());
    WAIT_FOR(policyMgr.contractExists(con5->getURI()), 500);

    mac_address_t vmac1("00:01:02:03:04:05");
    mac_address_t vmac2("01:02:03:04:05:06");
    gbp_rule::next_hop_t nh1(address::from_string("1.1.1.1"), vmac1, 100, 100);
    gbp_rule::next_hop_t nh2(address::from_string("2.2.2.2"), vmac2, 100, 100);
    gbp_rule::next_hops_t nhs({nh1, nh2});
    gbp_rule::next_hop_set_t next_hop_set(gbp_rule::hash_mode_t::SYMMETRIC,
                                          nhs);
    gbp_rule gr(8192, next_hop_set, gbp_rule::action_t::REDIRECT);
    gbp_contract::gbp_rules_t gbp_rules = {gr};

    gbp_contract::ethertype_set_t e_rules = {ethertype_t::IPV4};

    ACL::action_t act = ACL::action_t::DENY;
    ACL::l3_rule rule1(8192,
                       act,
                       route::prefix_t::ZERO,
                       route::prefix_t::ZERO,
                       6,
                       0,
                       65535,
                       80,
                       65535,
                       0,
                       0);
    ACL::l3_list::rules_t rules1({rule1});

    ACL::l3_list outAcl(con5->getURI().toString() + "out", rules1);
    WAIT_FOR_MATCH(outAcl);

    gbp_contract gbpc(2571, 2570, outAcl, gbp_rules, e_rules);

    WAIT_FOR1(is_match(gbpc));
}

BOOST_AUTO_TEST_SUITE_END()

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */
