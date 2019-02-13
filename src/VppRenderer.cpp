/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for VPPRenderer class
 *
 * Copyright (c) 2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#include <boost/asio/placeholders.hpp>

#include <opflexagent/logging.h>

#include <vom/stat_reader.hpp>

#include "VppLogHandler.hpp"
#include "VppRenderer.hpp"

namespace VPP
{

using boost::asio::placeholders::error;
using boost::property_tree::ptree;
using opflex::ofcore::OFFramework;
using std::bind;

VppRendererPlugin::VppRendererPlugin()
{
}

std::unordered_set<std::string>
VppRendererPlugin::getNames() const
{
    return {"vpp"};
}

opflexagent::Renderer *
VppRendererPlugin::create(opflexagent::Agent &agent) const
{
    IdGenerator *idGen = new IdGenerator();
    VOM::HW::cmd_q *vppQ = new VOM::HW::cmd_q();
    VOM::stat_reader *vppSR = new stat_reader();
    VppManager *vppManager = new VppManager(agent, *idGen, vppQ, vppSR);
    return new VppRenderer(agent, *idGen, vppManager);
}

VPP::LogHandler vppLogHandler;

static VOM::log_level_t
agentLevelToVom(opflexagent::LogLevel level)
{
    switch (level)
    {
    case opflexagent::DEBUG:
        return (VOM::log_level_t::DEBUG);
    case opflexagent::INFO:
        return (VOM::log_level_t::INFO);
    case opflexagent::WARNING:
        return (VOM::log_level_t::WARNING);
    case opflexagent::ERROR:
        return (VOM::log_level_t::ERROR);
    case opflexagent::FATAL:
        return (VOM::log_level_t::CRITICAL);
    }
    return (VOM::log_level_t::INFO);
}

VppRenderer::VppRenderer(opflexagent::Agent &agent,
                         IdGenerator &idGen,
                         VppManager *vppManager)
    : Renderer(agent)
    , idGen(idGen)
    , vppManager(vppManager)
    , started(false)
{
    LOG(INFO) << "Vpp Renderer";

    /*
     * Register the call back handler for VOM logging and set the level
     * according to the agent's settings
     */
    VOM::logger().set(agentLevelToVom(opflexagent::logLevel));
    VOM::logger().set(&vppLogHandler);
}

VppRenderer::~VppRenderer()
{
    delete vppManager;
}

void
VppRenderer::setProperties(const boost::property_tree::ptree &properties)
{
    // Set configuration from property tree.  This configuration will
    // be from a "renderers": { "vpp" { } } block from the agent
    // configuration.  Multiple calls are possible; later calls are
    // merged with prior calls, overwriting any previously-set values.
    LOG(opflexagent::INFO) << "Setting configuration for vpp renderer";
    static const std::string ENCAP_VXLAN("encap.vxlan");
    static const std::string ENCAP_IVXLAN("encap.ivxlan");
    static const std::string ENCAP_VLAN("encap.vlan");
    static const std::string UPLINK_IFACE("uplink-iface");
    static const std::string UPLINK_SLAVES("uplink-slaves");
    static const std::string UPLINK_VLAN("uplink-vlan");
    static const std::string DHCP_OPTIONS("dhcp-opt");
    static const std::string ENCAP_IFACE("encap-iface");
    static const std::string REMOTE_IP("remote-ip");
    static const std::string REMOTE_PORT("remote-port");
    static const std::string VIRTUAL_ROUTER("forwarding"
                                            ".virtual-router.enabled");
    static const std::string VIRTUAL_ROUTER_MAC("forwarding"
                                                ".virtual-router.mac");
    static const std::string VIRTUAL_ROUTER_RA("forwarding.virtual-router"
                                               ".ipv6.router-advertisement");
    static const std::string CROSS_CONNECT("x-connect");
    static const std::string EAST("east");
    static const std::string WEST("west");
    static const std::string EIFACE("iface");
    static const std::string EVLAN("vlan");
    static const std::string EIP("ip-address");
    static const std::string ETAG_REWRITE("tag-rewrite");
    static const std::string WIFACE("iface");
    static const std::string WVLAN("vlan");
    static const std::string WIP("ip-address");

    auto vxlan = properties.get_child_optional(ENCAP_VXLAN);
    auto vlan = properties.get_child_optional(ENCAP_VLAN);
    auto vr = properties.get_child_optional(VIRTUAL_ROUTER);
    auto x_connect = properties.get_child_optional(CROSS_CONNECT);

    if (vlan)
    {
        vppManager->uplink().set(vlan.get().get<std::string>(UPLINK_IFACE, ""),
                                 vlan.get().get<uint16_t>(UPLINK_VLAN, 0),
                                 vlan.get().get<std::string>(ENCAP_IFACE, ""));
        auto slaves = vlan.get().get_child_optional(UPLINK_SLAVES);

        if (slaves)
        {
            for (auto s : slaves.get())
            {
                vppManager->uplink().insert_slave_ifaces(s.second.data());
                LOG(opflexagent::INFO) << s.second.data();
            }
        }
        auto dhcp_options = vlan.get().get_child_optional(DHCP_OPTIONS);
        if (dhcp_options)
        {
            for (auto d : dhcp_options.get())
            {
                vppManager->uplink().insert_dhcp_options(d.second.data());
                LOG(opflexagent::INFO) << d.second.data();
            }
        }
    }
    else if (vxlan)
    {
        boost::asio::ip::address remote_ip;
        boost::system::error_code ec;

        remote_ip = boost::asio::ip::address::from_string(
            vxlan.get().get<std::string>(REMOTE_IP, ""));

        if (ec)
        {
            LOG(ERROR) << "Invalid tunnel destination IP: "
                       << vxlan.get().get<std::string>(REMOTE_IP, "") << ": "
                       << ec.message();
        }
        else
        {
            vppManager->uplink().set(
                vxlan.get().get<std::string>(UPLINK_IFACE, ""),
                vxlan.get().get<uint16_t>(UPLINK_VLAN, 0),
                vxlan.get().get<std::string>(ENCAP_IFACE, ""),
                remote_ip,
                vxlan.get().get<uint16_t>(REMOTE_PORT, 4789));
            auto slaves = properties.get_child_optional(UPLINK_SLAVES);
        }
    }
    if (vr)
    {
        vppManager->setVirtualRouter(
            vr.get().get<bool>(VIRTUAL_ROUTER, true),
            vr.get().get<bool>(VIRTUAL_ROUTER_RA, true),
            vr.get().get<std::string>(VIRTUAL_ROUTER_MAC, "00:22:bd:f8:19:ff"));
    }

    if (x_connect)
    {
        for (auto x : x_connect.get())
        {
            auto east = x.second.get_child_optional(EAST);
            auto west = x.second.get_child_optional(WEST);
            if (east && west)
            {
                std::string ename = east.get().get<std::string>(EIFACE, "");
                uint16_t evlan = east.get().get<uint16_t>(EVLAN, 0);
                std::string eip = east.get().get<std::string>(EIP, "0.0.0.0");
                std::string etag_rewrite =
                    east.get().get<std::string>(ETAG_REWRITE, "");
                std::string wname = west.get().get<std::string>(WIFACE, "");
                uint16_t wvlan = west.get().get<uint16_t>(WVLAN, 0);
                std::string wip = west.get().get<std::string>(WIP, "0.0.0.0");
                LOG(opflexagent::DEBUG)
                    << "east:[" << ename << " , " << evlan << " , " << eip
                    << " , " << etag_rewrite << "]";
                LOG(opflexagent::DEBUG) << "west:[" << wname << " , " << wvlan
                                        << " , " << wip << "]";
                if (!ename.empty() && !wname.empty())
                {
                    VPP::CrossConnect::xconnect_t xcon_east(
                        ename, evlan, eip, etag_rewrite);
                    VPP::CrossConnect::xconnect_t xcon_west(wname, wvlan, wip);
                    vppManager->crossConnect().insert_xconnect(
                        std::make_pair(xcon_east, xcon_west));
                }
            }
        }
    }

    /*
     * Are we opening an inspection socket?
     */
    auto inspect = properties.get<std::string>("inspect-socket", "");

    if (inspect.length())
    {
        inspector.reset(new VppInspect(inspect));
    }
}

void
VppRenderer::start()
{
    // Called during agent startup
    if (started) return;
    started = true;
    vppManager->start();
    vppManager->registerModbListeners();
    LOG(opflexagent::INFO) << "Starting vpp renderer plugin";
}

void
VppRenderer::stop()
{
    // Called during agent shutdown
    if (!started) return;
    started = false;
    LOG(opflexagent::INFO) << "Stopping vpp renderer plugin";
    vppManager->stop();
}

} // namespace VPP

extern "C" const opflexagent::RendererPlugin *
init_renderer_plugin()
{
    // Return a plugin implementation, which can ini
    static const VPP::VppRendererPlugin vppPlugin;

    return &vppPlugin;
}
