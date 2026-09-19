# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

add_library(launch_as_terminal STATIC
    TerminalBridge.cpp
    TerminalBridge.h
    TerminalIO.cpp
    TerminalIO.h
)
add_library(launch_as::terminal ALIAS launch_as_terminal)

configure_launch_as_module(launch_as_terminal "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(launch_as_terminal PUBLIC
    launch_as::common
)
