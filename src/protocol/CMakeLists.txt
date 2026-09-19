# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

add_library(launch_as_protocol STATIC
    BrokerControlPipe.cpp
    BrokerControlPipe.h
    BrokerProtocol.cpp
    BrokerProtocol.h
    PseudoConsoleHostReport.h
)
add_library(launch_as::protocol ALIAS launch_as_protocol)

configure_launch_as_module(launch_as_protocol "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(launch_as_protocol PRIVATE
    launch_as::common
)
