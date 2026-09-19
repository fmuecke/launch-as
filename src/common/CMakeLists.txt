# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

add_library(launch_as_common STATIC
    ExitCodes.h
    LicenseHeader.cpp
    LicenseHeader.h
    TerminalEndpoints.h
    Utf8.h
    Win32Support.cpp
    Win32Support.h
    WindowsCommandLine.cpp
    WindowsCommandLine.h
)
add_library(launch_as::common ALIAS launch_as_common)

configure_launch_as_module(launch_as_common "${CMAKE_CURRENT_SOURCE_DIR}")
target_include_directories(launch_as_common PRIVATE
    "${PROJECT_BINARY_DIR}"
)
