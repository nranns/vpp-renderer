#
# renderer-vpp: Vpp OpFlex agent renderer plugin
# Copyright (c) 2018 Cisco Systems, Inc. and others.  All rights reserved.
#
# This program and the accompanying materials are made available under the
# terms of the Eclipse Public License v1.0 which accompanies this distribution,
# and is available at http://www.eclipse.org/legal/epl-v10.html
#
###########
#
# Process this file with automake to produce a Makefile.in

ACLOCAL_AMFLAGS = -I m4

VPP_ADDL_CFLAGS = \
        -D__STDC_LIMIT_MACROS \
        -D__STDC_CONSTANT_MACROS \
        -I/usr/include/vpp_plugins \
        -fpermissive

# Create a convenience library containing our plugin sources
noinst_LTLIBRARIES = librenderer_vpp.la
librenderer_vpp_la_CXXFLAGS = \
	$(libopflex_agent_CFLAGS) \
        $(VPP_ADDL_CFLAGS) \
        -Isrc/include
librenderer_vpp_la_LIBADD = \
	$(libopflex_agent_LIBS)

noinst_HEADERS = \
       src/include/VppContractManager.hpp \
       src/include/VppCrossConnect.hpp \
       src/include/VppEndPointGroupManager.hpp \
       src/include/VppEndPointManager.hpp \
       src/include/VppExtItfManager.hpp \
       src/include/VppIdGen.hpp \
       src/include/VppInspect.hpp \
       src/include/VppLog.hpp \
       src/include/VppLogHandler.hpp \
       src/include/VppManager.hpp \
       src/include/VppRenderer.hpp \
       src/include/VppRouteManager.hpp \
       src/include/VppRuntime.hpp \
       src/include/VppSecurityGroupManager.hpp \
       src/include/VppSpineProxy.hpp \
       src/include/VppUplink.hpp \
       src/include/VppUtil.hpp \
       src/include/VppVirtualRouter.hpp

librenderer_vpp_la_SOURCES = \
	src/VppContractManager.cpp \
	src/VppCrossConnect.cpp \
	src/VppEndPointGroupManager.cpp \
	src/VppEndPointManager.cpp \
	src/VppExtItfManager.cpp \
        src/VppIdGen.cpp \
        src/VppInspect.cpp \
        src/VppLogHandler.cpp \
        src/VppManager.cpp \
	src/VppRenderer.cpp \
        src/VppRouteManager.cpp \
        src/VppSecurityGroupManager.cpp \
        src/VppSpineProxy.cpp \
        src/VppUplink.cpp \
        src/VppUtil.cpp \
        src/VppVirtualRouter.cpp

# Link the convenience library into an installable module
lib_LTLIBRARIES = libopflex_agent_renderer_vpp.la
libopflex_agent_renderer_vpp_la_LIBADD = \
	librenderer_vpp.la
libopflex_agent_renderer_vpp_la_SOURCES =
libopflex_agent_renderer_vpp_la_LDFLAGS = \
	-avoid-version -module -shared

# Install the default plugin configuration file
pluginconfdir=$(sysconfdir)/opflex-agent-ovs/plugins.conf.d
pluginconf_DATA = plugin-renderer-vpp.conf

plugin-renderer-vpp.conf: $(top_srcdir)/plugin-renderer-vpp.conf.in

fixstyle:
	clang-format -i src/*.cpp
	clang-format -i src/test/*.cpp
	clang-format -i src/include/*.hpp

# Create a unit test driver that links to the plugin convenience
# library
TESTS = vpp_test
noinst_PROGRAMS = $(TESTS)
vpp_test_CXXFLAGS = \
        -I$(top_srcdir)/lib/include \
        -I$(top_srcdir)/cmd/test/include \
        -Isrc/include \
	$(libopflex_agent_CFLAGS) \
        $(VPP_ADDL_CFLAGS) \
	-DBOOST_TEST_DYN_LINK
vpp_test_LDADD = \
        $(BOOST_FILESYSTEM_LIB) \
        $(BOOST_SYSTEM_LIB) \
	$(libopflex_agent_LIBS) \
	$(BOOST_UNIT_TEST_FRAMEWORK_LIB) \
        librenderer_vpp.la
vpp_test_SOURCES = \
	src/test/vpp_test.cpp \
	src/test/VppRenderer_test.cpp \
        src/test/VppManager_test.cpp

clean-local:
	rm -rf *.rpm

CWD=`pwd`
RPMFLAGS=--define "_topdir ${CWD}/rpm"
ARCH=x86_64
SOURCE_FILE=${PACKAGE}-${VERSION}.tar.gz
RPMDIRS=rpm/BUILD rpm/SOURCES rpm/RPMS rpm/SRPMS
rpm: dist rpm/opflex-agent-renderer-vpp.spec
	mkdir -p ${RPMDIRS}
	cp ${SOURCE_FILE} rpm/SOURCES/
	rpmbuild ${RPMFLAGS} -ba rpm/opflex-agent-renderer-vpp.spec
	cp rpm/RPMS/${ARCH}/*.rpm .
	cp rpm/SRPMS/*.rpm .
	rm -rf ${RPMDIRS}

srpm: dist rpm/opflex-agent-renderer-vpp.spec
	mkdir -p ${RPMDIRS}
	cp ${SOURCE_FILE} rpm/SOURCES/
	rpmbuild ${RPMFLAGS} -bs rpm/opflex-agent-renderer-vpp.spec
	cp rpm/SRPMS/*.rpm .
	rm -rf ${RPMDIRS}
