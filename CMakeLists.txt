# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

cmake_minimum_required(VERSION 3.25)

project(
    launch_as
    VERSION 0.3.2
    LANGUAGES CXX RC
)

set(LAUNCH_AS_VERSION_TWEAK 0)

if(NOT WIN32)
    message(FATAL_ERROR "launch-as supports Windows only.")
endif()

include(CTest)

configure_file(
    resources/LauncherVersion.rc.in
    "${CMAKE_CURRENT_BINARY_DIR}/LauncherVersion.rc"
    @ONLY
)
configure_file(
    resources/LauncherVersion.h.in
    "${CMAKE_CURRENT_BINARY_DIR}/LauncherVersion.h"
    @ONLY
)
configure_file(
    resources/Launcher.manifest
    "${CMAKE_CURRENT_BINARY_DIR}/Launcher.manifest"
    COPYONLY
)

add_executable(launch_as
    src/CredentialInput.cpp
    src/CredentialInput.h
    src/Credentials.cpp
    src/Credentials.h
    src/launch_as.cpp
    src/LauncherOptions.cpp
    src/LauncherOptions.h
    src/PseudoConsoleHost.cpp
    src/PseudoConsoleHost.h
    src/PseudoConsoleSession.cpp
    src/PseudoConsoleSession.h
    src/LaunchProcess.cpp
    src/LaunchProcess.h
    src/TerminalBridge.cpp
    src/TerminalBridge.h
    src/TerminalIO.cpp
    src/TerminalIO.h
    src/Win32Support.cpp
    src/Win32Support.h
    src/WindowsCommandLine.cpp
    src/WindowsCommandLine.h
    "${CMAKE_CURRENT_BINARY_DIR}/LauncherVersion.rc"
)
target_include_directories(launch_as PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}"
)

function(configure_launch_as_target target)
    target_compile_features(${target} PRIVATE cxx_std_23)

    if(MSVC)
        target_compile_options(${target} PRIVATE
            /std:c++latest
            /W4
            /WX
            /permissive-
            /sdl
            /utf-8
            /MP
        )
        set_property(TARGET ${target} PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
        )
    else()
        message(FATAL_ERROR "Native targets currently require the MSVC toolchain.")
    endif()

    target_compile_definitions(${target} PRIVATE
        UNICODE
        _UNICODE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )

    set_target_properties(${target} PROPERTIES
        CXX_EXTENSIONS OFF
    )
endfunction()

target_link_libraries(launch_as PRIVATE
    Advapi32
    Credui
    Ole32
)
if(MSVC)
    target_link_options(launch_as PRIVATE
        "/MANIFESTINPUT:${CMAKE_CURRENT_BINARY_DIR}/Launcher.manifest"
    )
endif()

configure_launch_as_target(launch_as)
set_target_properties(launch_as PROPERTIES
    OUTPUT_NAME "launch-as"
)

if(BUILD_TESTING)
    add_executable(LauncherArgvProbe
        tests/ArgvProbe.cpp
    )
    configure_launch_as_target(LauncherArgvProbe)

    add_executable(LauncherTerminalSizeProbe
        tests/TerminalSizeProbe.cpp
    )
    configure_launch_as_target(LauncherTerminalSizeProbe)

    add_executable(LauncherCommandLineTests
        tests/CommandLineTests.cpp
        src/WindowsCommandLine.cpp
    )
    target_include_directories(LauncherCommandLineTests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests"
    )
    configure_launch_as_target(LauncherCommandLineTests)

    add_test(
        NAME launcher.command_line
        COMMAND
            "$<TARGET_FILE:LauncherCommandLineTests>"
            "$<TARGET_FILE:LauncherArgvProbe>"
    )
    set_tests_properties(launcher.command_line PROPERTIES
        LABELS "launcher;unit"
    )

    add_executable(LauncherManifestTests
        tests/ManifestTests.cpp
    )
    configure_launch_as_target(LauncherManifestTests)

    add_test(
        NAME launcher.manifest
        COMMAND
            "$<TARGET_FILE:LauncherManifestTests>"
            "$<TARGET_FILE:launch_as>"
    )
    set_tests_properties(launcher.manifest PROPERTIES
        LABELS "launcher;unit"
    )

    add_executable(LauncherPseudoConsoleTests
        tests/PseudoConsoleTests.cpp
        src/TerminalBridge.cpp
        src/TerminalIO.cpp
        src/Win32Support.cpp
        src/WindowsCommandLine.cpp
    )
    target_include_directories(LauncherPseudoConsoleTests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
    )
    configure_launch_as_target(LauncherPseudoConsoleTests)
    target_link_libraries(LauncherPseudoConsoleTests PRIVATE
        Advapi32
        Ole32
    )

    add_test(
        NAME launcher.pseudoconsole
        COMMAND
            "$<TARGET_FILE:LauncherPseudoConsoleTests>"
            "$<TARGET_FILE:launch_as>"
            "$<TARGET_FILE:LauncherTerminalSizeProbe>"
    )
    set_tests_properties(launcher.pseudoconsole PROPERTIES
        LABELS "launcher;integration;terminal"
        PASS_REGULAR_EXPRESSION "conpty-smoke-256"
        TIMEOUT 15
    )

    add_executable(LauncherTerminalDisconnectTests
        tests/TerminalDisconnectTests.cpp
        src/TerminalBridge.cpp
        src/TerminalIO.cpp
        src/Win32Support.cpp
        src/WindowsCommandLine.cpp
    )
    target_include_directories(LauncherTerminalDisconnectTests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
    )
    configure_launch_as_target(LauncherTerminalDisconnectTests)
    target_link_libraries(LauncherTerminalDisconnectTests PRIVATE
        Advapi32
        Ole32
    )

    add_test(
        NAME launcher.terminal_disconnect
        COMMAND
            "$<TARGET_FILE:LauncherTerminalDisconnectTests>"
            "$<TARGET_FILE:launch_as>"
    )
    set_tests_properties(launcher.terminal_disconnect PROPERTIES
        LABELS "launcher;integration;terminal"
        PASS_REGULAR_EXPRESSION "Terminal disconnect stopped the interactive helper"
        TIMEOUT 15
    )

    find_program(
        POWERSHELL_EXECUTABLE
        NAMES pwsh powershell
        REQUIRED
    )
    add_test(
        NAME launcher.behavior
        COMMAND
            "${POWERSHELL_EXECUTABLE}"
            -NoLogo
            -NoProfile
            -NonInteractive
            -ExecutionPolicy Bypass
            -File
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/Invoke-LauncherBehaviorTests.ps1"
            -LauncherPath
            "$<TARGET_FILE:launch_as>"
            -ExpectedVersion
            "${PROJECT_VERSION}"
            -ExpectedTestCredentialTagVisibility
            "$<IF:$<CONFIG:Debug>,Visible,Hidden>"
    )
    set_tests_properties(launcher.behavior PROPERTIES
        LABELS "launcher;behavior"
    )

endif()
