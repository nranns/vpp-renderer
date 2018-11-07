/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Include file for VPPRenderer
 *
 * Copyright (c) 2018 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef VPPRENDERER_H
#define VPPRENDERER_H

#include <opflexagent/IdGenerator.h>
#include <opflexagent/Renderer.h>
#include <boost/property_tree/ptree.hpp>
#include <opflex/ofcore/OFFramework.h>
#include <vom/hw.hpp>
#include "VppInspect.h"
#include "VppManager.h"

using namespace opflexagent;

namespace vpprenderer {

/**
 * The vpp renderer demonstrates how to create a renderer plugin
 * for OpFlex agent.
 */
class VPPRenderer : public opflexagent::Renderer {
public:
    /**
     * Instantiate a vpp renderer
     *
     * @param agent the agent object
     */
    VPPRenderer(opflexagent::Agent& agent, IdGenerator *idGen,
                VOM::HW::cmd_q *vppQ, VppManager *vppManager);

    /**
     * Destroy the renderer and clean up all state
     */
    virtual ~VPPRenderer();

    // ********
    // Renderer
    // ********

    virtual void setProperties(const boost::property_tree::ptree& properties);
    virtual void start();
    virtual void stop();

private:
    /**
     * The socket used for inspecting the state built in VPP-manager
     */
    std::unique_ptr<VppInspect> inspector;

    /**
     * ID generator
     */
    IdGenerator* idGen;

    /**
     * HW cmd_q
     */
    VOM::HW::cmd_q* vppQ;

    /**
     * Single instance of the VPP manager
     */
    VppManager* vppManager;

    /**
     * has this party started.
     */
    bool started;
};

/**
 * Plugin implementation for dynamically loading vpp
 * renderer.
 */
class VPPRendererPlugin : public opflexagent::RendererPlugin {
public:
    VPPRendererPlugin();

    // **************
    // RendererPlugin
    // **************
    virtual std::unordered_set<std::string> getNames() const;
    virtual opflexagent::Renderer* create(opflexagent::Agent& agent) const;
};

} /* namespace vpprenderer */

/**
 * Return a non-owning pointer to the renderer plugin instance.
 */
extern "C" const opflexagent::RendererPlugin* init_renderer_plugin();

#endif /* VPPRENDERER_H */
