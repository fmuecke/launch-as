# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

add_library(launch_as_broker_core STATIC
    BrokerAccountProvisioner.cpp
    BrokerAccountProvisioner.h
    BrokerApplication.cpp
    BrokerApplication.h
    BrokerAudit.cpp
    BrokerAudit.h
    BrokerCallerIdentity.h
    BrokerCallerPolicy.cpp
    BrokerCallerPolicy.h
    BrokerControlPipeListener.cpp
    BrokerControlPipeListener.h
    BrokerDataDirectory.cpp
    BrokerDataDirectory.h
    BrokerEnrollmentStore.cpp
    BrokerEnrollmentStore.h
    BrokerLogonToken.cpp
    BrokerLogonToken.h
    BrokerPassword.cpp
    BrokerPassword.h
    BrokerPipeServer.cpp
    BrokerPipeServer.h
    BrokerProcessLauncher.cpp
    BrokerProcessLauncher.h
    BrokerRegistration.cpp
    BrokerRegistration.h
    BrokerServiceRuntime.cpp
    BrokerServiceRuntime.h
)
add_library(launch_as::broker ALIAS launch_as_broker_core)

configure_launch_as_module(launch_as_broker_core "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(launch_as_broker_core
    PUBLIC
        launch_as::protocol
    PRIVATE
        launch_as::common
)
