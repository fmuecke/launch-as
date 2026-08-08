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
            /EHsc
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

add_executable(launch_as_broker
    src/BrokerAccountProvisioner.cpp
    src/BrokerAccountProvisioner.h
    src/BrokerCredentialStore.cpp
    src/BrokerCredentialStore.h
    src/BrokerDataDirectory.cpp
    src/BrokerDataDirectory.h
    src/BrokerLogonToken.cpp
    src/BrokerLogonToken.h
    src/BrokerPassword.cpp
    src/BrokerPassword.h
    src/BrokerRegistration.cpp
    src/BrokerRegistration.h
    src/BrokerServiceInstaller.cpp
    src/BrokerServiceInstaller.h
    src/BrokerPipeServer.cpp
    src/BrokerPipeServer.h
    src/BrokerProtocol.cpp
    src/BrokerProtocol.h
    src/BrokerService.cpp
    src/Win32Support.cpp
    src/Win32Support.h
)
target_link_libraries(launch_as_broker PRIVATE
    Advapi32
    Bcrypt
    Crypt32
    Netapi32
    Ole32
    Shell32
)
configure_launch_as_target(launch_as_broker)
set_target_properties(launch_as_broker PROPERTIES
    OUTPUT_NAME "launch-as-broker"
)

if(BUILD_TESTING)
    add_executable(LauncherBrokerProtocolTests
        tests/BrokerProtocolTests.cpp
        src/BrokerProtocol.cpp
        src/BrokerProtocol.h
    )
    target_include_directories(LauncherBrokerProtocolTests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
    )
    configure_launch_as_target(LauncherBrokerProtocolTests)

    add_test(
        NAME launcher.broker_protocol
        COMMAND "$<TARGET_FILE:LauncherBrokerProtocolTests>"
    )
    set_tests_properties(launcher.broker_protocol PROPERTIES
        LABELS "broker;unit"
    )

    add_executable(LauncherBrokerPipeTests
        tests/BrokerPipeTests.cpp
        src/BrokerPipeServer.cpp
        src/BrokerPipeServer.h
        src/BrokerProtocol.cpp
        src/Win32Support.cpp
    )
    target_include_directories(LauncherBrokerPipeTests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
    )
    target_link_libraries(LauncherBrokerPipeTests PRIVATE
        Advapi32
    )
    configure_launch_as_target(LauncherBrokerPipeTests)

    add_test(
        NAME launcher.broker_pipe
        COMMAND "$<TARGET_FILE:LauncherBrokerPipeTests>"
    )
    set_tests_properties(launcher.broker_pipe PROPERTIES
        LABELS "broker;integration"
    )

    add_executable(LauncherBrokerCommandTests
        tests/BrokerCommandTests.cpp
        src/BrokerPipeServer.cpp
        src/BrokerPipeServer.h
        src/BrokerProtocol.cpp
        src/BrokerProtocol.h
        src/Win32Support.cpp
    )
    target_include_directories(LauncherBrokerCommandTests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
    )
    target_link_libraries(LauncherBrokerCommandTests PRIVATE
        Advapi32
    )
    configure_launch_as_target(LauncherBrokerCommandTests)

    add_test(
        NAME launcher.broker_command
        COMMAND
            "$<TARGET_FILE:LauncherBrokerCommandTests>"
            "$<TARGET_FILE:launch_as_broker>"
    )
    set_tests_properties(launcher.broker_command PROPERTIES
        LABELS "broker;integration"
    )

    add_executable(LauncherBrokerCredentialStoreTests
        tests/BrokerCredentialStoreTests.cpp
        src/BrokerCredentialStore.cpp
        src/BrokerCredentialStore.h
    )
    target_include_directories(LauncherBrokerCredentialStoreTests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
    )
    target_link_libraries(LauncherBrokerCredentialStoreTests PRIVATE
        Crypt32
    )
    configure_launch_as_target(LauncherBrokerCredentialStoreTests)

    add_test(
        NAME launcher.broker_credential_store
        COMMAND "$<TARGET_FILE:LauncherBrokerCredentialStoreTests>"
    )
    set_tests_properties(launcher.broker_credential_store PROPERTIES
        LABELS "broker;integration"
    )

    add_executable(LauncherBrokerPasswordTests
        tests/BrokerPasswordTests.cpp
        src/BrokerCredentialStore.cpp
        src/BrokerCredentialStore.h
        src/BrokerPassword.cpp
        src/BrokerPassword.h
    )
    target_include_directories(LauncherBrokerPasswordTests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
    )
    target_link_libraries(LauncherBrokerPasswordTests PRIVATE
        Bcrypt
        Crypt32
    )
    configure_launch_as_target(LauncherBrokerPasswordTests)

    add_test(
        NAME launcher.broker_password
        COMMAND "$<TARGET_FILE:LauncherBrokerPasswordTests>"
    )
    set_tests_properties(launcher.broker_password PROPERTIES
        LABELS "broker;unit"
    )

    add_executable(LauncherBrokerDataDirectoryTests
        tests/BrokerDataDirectoryTests.cpp
        src/BrokerDataDirectory.cpp
        src/BrokerDataDirectory.h
    )
    target_include_directories(LauncherBrokerDataDirectoryTests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
    )
    target_link_libraries(LauncherBrokerDataDirectoryTests PRIVATE
        Advapi32
    )
    configure_launch_as_target(LauncherBrokerDataDirectoryTests)

    add_test(
        NAME launcher.broker_data_directory
        COMMAND "$<TARGET_FILE:LauncherBrokerDataDirectoryTests>"
    )
    set_tests_properties(launcher.broker_data_directory PROPERTIES
        LABELS "broker;integration"
    )

    add_executable(LauncherBrokerAccountProvisioningTests
        tests/BrokerAccountProvisioningTests.cpp
        src/BrokerAccountProvisioner.cpp
        src/BrokerAccountProvisioner.h
        src/BrokerCredentialStore.cpp
        src/BrokerCredentialStore.h
        src/BrokerLogonToken.cpp
        src/BrokerLogonToken.h
        src/BrokerPassword.cpp
        src/BrokerPassword.h
        src/BrokerRegistration.cpp
        src/BrokerRegistration.h
    )
    target_include_directories(LauncherBrokerAccountProvisioningTests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
    )
    target_link_libraries(LauncherBrokerAccountProvisioningTests PRIVATE
        Bcrypt
        Crypt32
        Netapi32
        Advapi32
    )
    configure_launch_as_target(LauncherBrokerAccountProvisioningTests)

    add_executable(LauncherBrokerServiceInstallerTests
        tests/BrokerServiceInstallerTests.cpp
        src/BrokerServiceInstaller.cpp
        src/BrokerServiceInstaller.h
    )
    target_include_directories(LauncherBrokerServiceInstallerTests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
    )
    target_link_libraries(LauncherBrokerServiceInstallerTests PRIVATE
        Advapi32
        Ole32
        Shell32
    )
    configure_launch_as_target(LauncherBrokerServiceInstallerTests)

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
