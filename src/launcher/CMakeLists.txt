# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

add_library(launch_as_launcher_core STATIC
    BrokerControlClient.cpp
    BrokerControlClient.h
    InteractiveDesktopAclLease.cpp
    InteractiveDesktopAclLease.h
    InteractiveDesktopLeaseCoordinator.cpp
    InteractiveDesktopLeaseCoordinator.h
    LauncherOptions.cpp
    LauncherOptions.h
    LaunchProcess.cpp
    LaunchProcess.h
)
add_library(launch_as::launcher ALIAS launch_as_launcher_core)

configure_launch_as_module(launch_as_launcher_core "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(launch_as_launcher_core
    PUBLIC
        launch_as::common
    PRIVATE
        Advapi32
        User32
        launch_as::protocol
        launch_as::terminal
)
