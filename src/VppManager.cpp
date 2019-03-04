/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <memory>
#include <sstream>
#include <string>

#include <boost/asio/ip/host_name.hpp>
#include <boost/asio/placeholders.hpp>
#include <boost/functional/hash.hpp>
#include <boost/system/error_code.hpp>

#include "VppContractManager.hpp"
#include "VppEndPointGroupManager.hpp"
#include "VppEndPointManager.hpp"
#include "VppIdGen.hpp"
#include "VppLog.hpp"
#include "VppManager.hpp"
#include "VppRouteManager.hpp"
#include "VppSecurityGroupManager.hpp"
#include "VppExtItfManager.hpp"

#include <opflexagent/EndpointManager.h>

using std::bind;
using boost::asio::placeholders::error;

namespace VPP
{
/**
 * An owner of the objects VPP learns during boot-up
 */
static const std::string BOOT_KEY = "__boot__";

VppManager::VppManager(opflexagent::Agent &agent_,
                       opflexagent::IdGenerator &idGen_,
                       VOM::HW::cmd_q *q,
                       VOM::stat_reader *sr)
    : m_runtime(agent_, idGen_)
    , m_task_queue(agent_.getAgentIOService())
    , stopping(false)
{
    VOM::HW::init(q, sr);
    VOM::OM::init();

    m_runtime.system_name = boost::asio::ip::host_name();
    m_runtime.agent.getFramework().registerPeerStatusListener(this);
}

VppManager::~VppManager()
{
    VLOGE << "VppManager exiting";
}

void
VppManager::start()
{
    VLOGI << "start vpp manager; mode:"
          << (int)m_runtime.agent.getRendererForwardingMode();

    /*
     * create the update delegators
     */
    m_runtime.is_transport_mode =
        (opflex::ofcore::OFConstants::TRANSPORT_MODE == m_runtime.agent.getRendererForwardingMode());
    m_epm = std::make_shared<EndPointManager>(m_runtime);
    m_epgm = std::make_shared<EndPointGroupManager>(m_runtime);
    m_sgm = std::make_shared<SecurityGroupManager>(m_runtime.agent);
    m_cm = std::make_shared<ContractManager>(m_runtime.agent, m_runtime.id_gen);
    m_rdm = std::make_shared<RouteManager>(m_runtime);
    m_eim = std::make_shared<ExtItfManager>(m_runtime);

    initPlatformConfig();

    /*
     * make sure the first event in the task Q is the blocking
     * connection initiation to VPP ...
     */
    m_task_queue.dispatch("init-connection",
                          bind(&VppManager::handleInitConnection, this));

    /**
     * DO BOOT
     */

    /**
     * ... followed by vpp boot dump
     */
    m_task_queue.dispatch("boot-dump", bind(&VppManager::handleBoot, this));

    /**
     * ... followed by uplink configuration
     */
    m_task_queue.dispatch("uplink-configure",
                          bind(&VppManager::handleUplinkConfigure, this));

    /**
     * ... followed by cross connect configuration
     */
    m_task_queue.dispatch("xconnect-configure",
                          bind(&VppManager::handleXConnectConfigure, this));
}

void
VppManager::handleCloseConnection()
{
    if (!hw_connected) return;

    VOM::interface::disable_events();
    VOM::HW::disconnect();

    VLOGD << "Close VPP connection";
}

void
VppManager::handleInitConnection()
{
    if (stopping) return;

    VLOGD << "Open VPP connection";

    while (VOM::HW::connect() != true)
        ;

    hw_connected = true;

    /**
     * We are insterested in getting interface events from VPP
     */
    VOM::interface::enable_events(*this);

    /**
     * Scehdule a timer to Poll for HW livensss
     */
    m_poll_timer.reset(
        new boost::asio::deadline_timer(m_runtime.agent.getAgentIOService()));
    m_poll_timer->expires_from_now(boost::posix_time::seconds(3));
    m_poll_timer->async_wait(bind(&VppManager::handleHWPollTimer, this, error));

    /**
     * Scehdule a timer for HW stats
     */
    m_stats_timer.reset(
        new boost::asio::deadline_timer(m_runtime.agent.getAgentIOService()));
    m_stats_timer->expires_from_now(boost::posix_time::seconds(5));
    m_stats_timer->async_wait(
        bind(&VppManager::handleHWStatsTimer, this, error));
}

void
VppManager::handleUplinkConfigure()
{
    if (stopping) return;

    m_runtime.uplink.configure(m_runtime.system_name);
}

void
VppManager::handleXConnectConfigure()
{
    if (stopping) return;

    m_xconnect.configure_xconnect();
}

void
VppManager::handleSweepTimer(const boost::system::error_code &ec)
{
    if (stopping || ec) return;

    VLOGI << "sweep boot data";

    /*
     * the sweep timer was not cancelled, continue with purging old state.
     */
    if (hw_connected)
        VOM::OM::sweep(BOOT_KEY);
    else if (!stopping)
    {
        m_sweep_timer.reset(new boost::asio::deadline_timer(
            m_runtime.agent.getAgentIOService()));
        m_sweep_timer->expires_from_now(boost::posix_time::seconds(30));
        m_sweep_timer->async_wait(
            bind(&VppManager::handleSweepTimer, this, error));
    }
}

void
VppManager::handleHWPollTimer(const boost::system::error_code &ec)
{
    if (stopping || ec) return;

    if (hw_connected && VOM::HW::poll())
    {
        /*
         * re-scehdule a timer to Poll for HW liveness
         */
        m_poll_timer.reset(new boost::asio::deadline_timer(
            m_runtime.agent.getAgentIOService()));
        m_poll_timer->expires_from_now(boost::posix_time::seconds(3));
        m_poll_timer->async_wait(
            bind(&VppManager::handleHWPollTimer, this, error));
        return;
    }

    hw_connected = false;
    VOM::HW::disconnect();
    VLOGD << "Reconnecting ....";
    if (VOM::HW::connect())
    {
        VLOGD << "Replay the state after reconnecting ...";
        VOM::OM::replay();
        hw_connected = true;
    }

    if (!stopping)
    {
        m_poll_timer.reset(new boost::asio::deadline_timer(
            m_runtime.agent.getAgentIOService()));
        m_poll_timer->expires_from_now(boost::posix_time::seconds(1));
        m_poll_timer->async_wait(
            bind(&VppManager::handleHWPollTimer, this, error));
    }
    else
    {
        VOM::HW::disconnect();
    }
}

void
VppManager::handleHWStatsTimer(const boost::system::error_code &ec)
{
    if (stopping || ec) return;

    VLOGD << "stats reading";

    VOM::HW::read_stats();

    m_stats_timer.reset(
        new boost::asio::deadline_timer(m_runtime.agent.getAgentIOService()));
    m_stats_timer->expires_from_now(boost::posix_time::seconds(5));
    m_stats_timer->async_wait(
        bind(&VppManager::handleHWStatsTimer, this, error));
}

void
VppManager::handleBoot()
{
    if (stopping) return;

    /**
     * Read the state from VPP
     */
    VOM::OM::populate(BOOT_KEY);
}

void
VppManager::registerModbListeners()
{
    // Initialize policy listeners
    m_runtime.agent.getEndpointManager().registerListener(this);
    m_runtime.agent.getServiceManager().registerListener(this);
    m_runtime.agent.getExtraConfigManager().registerListener(this);
    m_runtime.agent.getPolicyManager().registerListener(this);
}

void
VppManager::stop()
{
    stopping = true;

    m_runtime.agent.getEndpointManager().unregisterListener(this);
    m_runtime.agent.getServiceManager().unregisterListener(this);
    m_runtime.agent.getExtraConfigManager().unregisterListener(this);
    m_runtime.agent.getPolicyManager().unregisterListener(this);

    if (m_stats_timer)
    {
        m_stats_timer->cancel();
    }

    if (m_sweep_timer)
    {
        m_sweep_timer->cancel();
    }

    if (m_poll_timer)
    {
        m_poll_timer->cancel();
    }

    m_task_queue.dispatch("close-connection",
                          bind(&VppManager::handleCloseConnection, this));

    VLOGD << "stop VppManager";
}

void
VppManager::setVirtualRouter(bool virtualRouterEnabled,
                             bool routerAdv,
                             const std::string &virtualRouterMac)
{
    if (virtualRouterEnabled)
    {
        m_runtime.vr = std::make_shared<VirtualRouter>(virtualRouterMac);
    }
}

void
VppManager::endpointUpdated(const std::string &uuid)
{
    if (stopping) return;

    m_task_queue.dispatch(uuid,
                          bind(&EndPointManager::handle_update, m_epm, uuid));
}

void
VppManager::externalEndpointUpdated(const std::string &uuid)
{
    if (stopping) return;

    m_task_queue.dispatch(uuid,
                          bind(&EndPointManager::handle_external_update, m_epm, uuid));
}

void
VppManager::remoteEndpointUpdated(const std::string &uuid)
{
    if (stopping) return;

    m_task_queue.dispatch(uuid,
                          bind(&EndPointManager::handle_remote_update, m_epm, uuid));
}

void
VppManager::serviceUpdated(const std::string &uuid)
{
    if (stopping) return;

    VLOGI << "Service Update Not supported ";
}

void
VppManager::rdConfigUpdated(const opflex::modb::URI &rdURI)
{
    m_task_queue.dispatch(
        rdURI.toString(),
        bind(&RouteManager::handle_domain_update, m_rdm, rdURI));
}

void
VppManager::egDomainUpdated(const opflex::modb::URI &egURI)
{
    if (stopping) return;

    m_task_queue.dispatch(
        egURI.toString(),
        bind(&EndPointGroupManager::handle_update, m_epgm, egURI));
}

void
VppManager::domainUpdated(opflex::modb::class_id_t cid,
                          const opflex::modb::URI &domURI)
{
    if (stopping) return;

    m_task_queue.dispatch(
        domURI.toString(),
        bind(&VppManager::handleDomainUpdate, this, cid, domURI));
}

void
VppManager::secGroupSetUpdated(const EndpointListener::uri_set_t &secGrps)
{
    if (stopping) return;
    m_task_queue.dispatch(
        "setSecGrp:",
        std::bind(&SecurityGroupManager::handle_set_update, m_sgm, secGrps));
}

void
VppManager::secGroupUpdated(const opflex::modb::URI &uri)
{
    if (stopping) return;
    m_task_queue.dispatch(
        "secGrp:", std::bind(&SecurityGroupManager::handle_update, m_sgm, uri));
}

void
VppManager::contractUpdated(const opflex::modb::URI &contractURI)
{
    if (stopping) return;
    m_task_queue.dispatch(
        contractURI.toString(),
        bind(&ContractManager::handle_update, m_cm, contractURI));
}

void
VppManager::externalInterfaceUpdated(const opflex::modb::URI &uri)
{
    if (stopping) return;
    m_task_queue.dispatch(
        uri.toString(),
        bind(&ExtItfManager::handle_update, m_eim, uri));
}

void
VppManager::staticRouteUpdated(const opflex::modb::URI &uri)
{
    if (stopping) return;
    m_task_queue.dispatch(
        uri.toString(),
        bind(&RouteManager::handle_static_update, m_rdm, uri));
}

void
VppManager::remoteRouteUpdated(const opflex::modb::URI &uri)
{
    if (stopping) return;
    m_task_queue.dispatch(
        uri.toString(),
        bind(&RouteManager::handle_remote_update, m_rdm, uri));
}

void
VppManager::handle_interface_event(std::vector<VOM::interface::event> e)
{
    if (stopping) return;
    m_task_queue.dispatch("InterfaceEvent",
                          bind(&VppManager::handleInterfaceEvent, this, e));
}

void
VppManager::configUpdated(const opflex::modb::URI &configURI)
{
    VLOGI << "Config Updated ";
    if (stopping) return;
    m_runtime.agent.getAgentIOService().dispatch(
        bind(&VppManager::handleConfigUpdate, this, configURI));
}

void
VppManager::portStatusUpdate(const std::string &portName,
                             uint32_t portNo,
                             bool fromDesc)
{
    if (stopping) return;
    m_runtime.agent.getAgentIOService().dispatch(
        bind(&VppManager::handlePortStatusUpdate, this, portName, portNo));
}

void
VppManager::peerStatusUpdated(const std::string &, int, PeerStatus peerStatus)
{
    if (stopping) return;
}

void
VppManager::handleDomainUpdate(opflex::modb::class_id_t cid,
                               const opflex::modb::URI &domURI)
{
    if (stopping) return;

    VLOGD << "Updating domain: " << domURI;

    switch (cid)
    {
    case modelgbp::gbp::RoutingDomain::CLASS_ID:
        m_rdm->handle_domain_update(domURI);
        break;
    case modelgbp::gbp::Subnet::CLASS_ID:
        if (!modelgbp::gbp::Subnet::resolve(m_runtime.agent.getFramework(),
                                            domURI))
        {
            VLOGD << "Cleaning up for Subnet: " << domURI;
        }
        break;
    case modelgbp::gbp::BridgeDomain::CLASS_ID:
        if (!modelgbp::gbp::BridgeDomain::resolve(
                m_runtime.agent.getFramework(), domURI))
        {
            VLOGD << "Cleaning up for BD: " << domURI;
            m_runtime.id_gen.erase(cid, domURI);
        }
        break;
    case modelgbp::gbp::FloodDomain::CLASS_ID:
        if (!modelgbp::gbp::FloodDomain::resolve(m_runtime.agent.getFramework(),
                                                 domURI))
        {
            VLOGD << "Cleaning up for FD: " << domURI;
            m_runtime.id_gen.erase(cid, domURI);
        }
        break;
    case modelgbp::gbp::L3ExternalNetwork::CLASS_ID:
        if (!modelgbp::gbp::L3ExternalNetwork::resolve(
                m_runtime.agent.getFramework(), domURI))
        {
            VLOGD << "Cleaning up for L3ExtNet: " << domURI;
            m_runtime.id_gen.erase(cid, domURI);
        }
        break;
    }
}

void
VppManager::handleInterfaceEvent(std::vector<VOM::interface::event> events)
{
    if (stopping) return;

    for (auto &e : events)
    {
        VLOGD << "Interface Event: " << e.itf.to_string()
              << " state: " << e.state.to_string();
    }
}

void
VppManager::initPlatformConfig()
{
    boost::optional<std::shared_ptr<modelgbp::platform::Config>> config =
        modelgbp::platform::Config::resolve(
            m_runtime.agent.getFramework(),
            m_runtime.agent.getPolicyManager().getOpflexDomain());
}

void
VppManager::handleConfigUpdate(const opflex::modb::URI &configURI)
{
    VLOGD << "Updating platform config " << configURI;
    if (stopping) return;

    initPlatformConfig();

    /**
     * Now that we are known to be opflex connected,
     * Scehdule a timer to sweep the state we read when we first connected
     * to VPP.
     */
    m_sweep_timer.reset(
        new boost::asio::deadline_timer(m_runtime.agent.getAgentIOService()));
    m_sweep_timer->expires_from_now(boost::posix_time::seconds(30));
    m_sweep_timer->async_wait(bind(&VppManager::handleSweepTimer, this, error));
}

void
VppManager::handlePortStatusUpdate(const std::string &portName, uint32_t)
{
    VLOGD << "Port-status update for " << portName;
    if (stopping) return;
}

Uplink &
VppManager::uplink()
{
    return m_runtime.uplink;
}
CrossConnect &
VppManager::crossConnect()
{
    return m_xconnect;
}

}; // namespace opflexagent

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */
