/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __VPP_MANAGER_H__
#define __VPP_MANAGER_H__

#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/noncopyable.hpp>
#include <boost/optional.hpp>

#include <vom/hw.hpp>
#include <vom/interface.hpp>
#include <vom/stat_reader.hpp>

#include <opflex/ofcore/PeerStatusListener.h>

#include <utility>

#include "opflexagent/Agent.h"
#include "opflexagent/EndpointManager.h"
#include "opflexagent/RDConfig.h"
#include "opflexagent/TaskQueue.h"

#include "VppCrossConnect.hpp"
#include "VppRuntime.hpp"

namespace VPP
{
class EndPointManager;
class EndPointGroupManager;
class SecurityGroupManager;
class ContractManager;
class RouteDomainManager;

/**
 * @brief Makes changes to VPP to be in sync with state of MOs.
 * Main function is to handling change notifications, generate a set
 * of config modifications that represent the changes and apply these
 * modifications.
 */
class VppManager : public opflexagent::EndpointListener,
                   public opflexagent::ServiceListener,
                   public opflexagent::ExtraConfigListener,
                   public opflexagent::PolicyListener,
                   public opflex::ofcore::PeerStatusListener,
                   public interface::event_listener,
                   private boost::noncopyable
{
  public:
    /**
     * Construct a new Vpp manager for the agent
     * @param agent the agent object
     * @param idGen the flow ID generator
     */
    VppManager(opflexagent::Agent &agent,
               opflexagent::IdGenerator &idGen,
               VOM::HW::cmd_q *q,
               VOM::stat_reader *sr);

    ~VppManager() = default;

    /**
     * Module start
     */
    virtual void start();

    /**
     * Installs listeners for receiving updates to MODB state.
     */
    virtual void registerModbListeners();

    /**
     * Module stop
     */
    virtual void stop();

    /**
     * Enable or disable the virtual routing
     *
     * @param virtualRouterEnabled true to enable the router
     * @param routerAdv true to enable IPv6 router advertisements
     * @param mac the MAC address to use as the router MAC formatted
     * as a colon-separated string of 6 hex-encoded bytes.
     */
    void setVirtualRouter(bool virtualRouterEnabled,
                          bool routerAdv,
                          const std::string &mac);

    /* Interface: EndpointListener */
    virtual void endpointUpdated(const std::string &uuid);

    /* Interface: ServiceListener */
    virtual void serviceUpdated(const std::string &uuid);

    /* Interface: ExtraConfigListener */
    virtual void rdConfigUpdated(const opflex::modb::URI &rdURI);

    /* Interface: PolicyListener */
    virtual void egDomainUpdated(const opflex::modb::URI &egURI);
    virtual void domainUpdated(opflex::modb::class_id_t cid,
                               const opflex::modb::URI &domURI);
    virtual void contractUpdated(const opflex::modb::URI &contractURI);
    virtual void configUpdated(const opflex::modb::URI &configURI);

    virtual void secGroupSetUpdated(const EndpointListener::uri_set_t &secGrps);
    virtual void secGroupUpdated(const opflex::modb::URI &);

    /* Interface: PortStatusListener */
    virtual void portStatusUpdate(const std::string &portName,
                                  uint32_t portNo,
                                  bool fromDesc);

    /**
     * Implementation for PeerStatusListener::peerStatusUpdated
     *
     * @param peerHostname the host name for the connection
     * @param peerPort the port number for the connection
     * @param peerStatus the new status for the connection
     */
    virtual void peerStatusUpdated(const std::string &peerHostname,
                                   int peerPort,
                                   PeerStatus peerStatus);

    /**
     * Return the uplink object
     */
    VPP::Uplink &uplink();

    /**
     * Return the cross connect object
     */
    VPP::CrossConnect &crossConnect();

  private:
    /**
     * Handle changes to a forwarding domain; only deals with
     * cleaning up when these objects are removed.
     *
     * @param cid Class of the forwarding domain
     * @param domURI URI of the changed forwarding domain
     */
    void handleDomainUpdate(opflex::modb::class_id_t cid,
                            const opflex::modb::URI &domURI);

    /**
     * Compare and update changes in platform config
     *
     * @param configURI URI of the changed contract
     */
    void handleConfigUpdate(const opflex::modb::URI &configURI);

    /**
     * Handle changes to port-status for endpoints and endpoint groups.
     *
     * @param portName Name of the port that changed
     * @param portNo Port number of the port that changed
     */
    void handlePortStatusUpdate(const std::string &portName, uint32_t portNo);

    /**
     * Event listener override to get Interface events
     */
    void handle_interface_event(std::vector<VOM::interface::event> e);

    /**
     * Handle interface event in the task-queue context
     */
    void handleInterfaceEvent(std::vector<VOM::interface::event> e);

    /**
     * Handle the connect request to VPP
     */
    void handleInitConnection();

    /**
     * Handle a disconnect from VPP request
     */
    void handleCloseConnection();

    /**
     * Handle the connect request to VPP
     */
    void handleUplinkConfigure();

    /**
     * Handle the cross connect requests to VPP
     */
    void handleXConnectConfigure();

    /**
     * Handle the Vpp Boot request
     */
    void handleBoot();

    /**
     * Handle the Vpp sweep timeout
     */
    void handleSweepTimer(const boost::system::error_code &ec);

    /**
     * Handle the HW poll timeout
     */
    void handleHWPollTimer(const boost::system::error_code &ec);

    /**
     * Pull the HW stats
     */
    void handleHWStatsTimer(const boost::system::error_code &ec);

    /*
     * A collection of runtime data that is available to the other managers
     */
    Runtime m_runtime;

    /**
     * The internal task-queue for handling the async upates
     */
    opflexagent::TaskQueue m_task_queue;

    /**
     * The sweep boot state timer.
     *  This is a member here so it has access to the taskQ
     */
    std::unique_ptr<boost::asio::deadline_timer> m_sweep_timer;

    /**
     * CrossConnect interface manager
     */
    VPP::CrossConnect m_xconnect;

    /**
     * The HW poll timer
     */
    std::unique_ptr<boost::asio::deadline_timer> m_poll_timer;

    /**
     * The HW stats timer
     */
    std::unique_ptr<boost::asio::deadline_timer> m_stats_timer;

    /**
     * indicator this manager is stopping
     */
    volatile bool stopping;

    /**
     * indicator for hw liveness
     */
    bool hw_connected;

    void initPlatformConfig();

    /**
     * objects to delegate task queu events to
     */
    std::shared_ptr<EndPointManager> m_epm;
    std::shared_ptr<EndPointGroupManager> m_epgm;
    std::shared_ptr<SecurityGroupManager> m_sgm;
    std::shared_ptr<ContractManager> m_cm;
    std::shared_ptr<RouteDomainManager> m_rdm;
};

} // namespace opflexagent

/*
 * Local Variables:
 * eval: (c-set-style "llvm.org")
 * End:
 */

#endif // VPPAGENT_VPPMANAGER_H_
