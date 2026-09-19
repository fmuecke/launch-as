# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

add_library(launch_as_conhost_core STATIC
    PseudoConsoleHost.cpp
    PseudoConsoleHost.h
    PseudoConsoleHostInvocation.cpp
    PseudoConsoleHostInvocation.h
    PseudoConsoleSession.cpp
    PseudoConsoleSession.h
)
add_library(launch_as::conhost ALIAS launch_as_conhost_core)

configure_launch_as_module(launch_as_conhost_core "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(launch_as_conhost_core
    PUBLIC
        launch_as::common
        launch_as::terminal
    PRIVATE
        launch_as::protocol
)
