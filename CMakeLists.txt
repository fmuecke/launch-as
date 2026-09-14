# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

cmake_minimum_required(VERSION 3.25)

project(
    launch_as
    VERSION 1.1.0
    LANGUAGES CXX RC
)

set(LAUNCH_AS_VERSION "${PROJECT_VERSION}")
#set(LAUNCH_AS_VERSION "${PROJECT_VERSION}-preview")
set(LAUNCH_AS_VERSION_TWEAK 0)

if(NOT WIN32)
    message(FATAL_ERROR "launch-as supports Windows only.")
endif()

include(CTest)

function(configure_launch_as_version_resource output description internal_name original_filename)
    set(LAUNCH_AS_FILE_DESCRIPTION "${description}")
    set(LAUNCH_AS_INTERNAL_NAME "${internal_name}")
    set(LAUNCH_AS_ORIGINAL_FILENAME "${original_filename}")
    configure_file(
        resources/LauncherVersion.rc.in
        "${CMAKE_CURRENT_BINARY_DIR}/${output}"
        @ONLY
    )
endfunction()

configure_launch_as_version_resource(
    LauncherVersion.rc
    "Least-privilege launcher"
    "launch-as"
    "launch-as.exe"
)
configure_launch_as_version_resource(
    LauncherConhostVersion.rc
    "launch-as console host"
    "launch-as-conhost"
    "launch-as-conhost.exe"
)
configure_launch_as_version_resource(
    LauncherBrokerVersion.rc
    "launch-as broker service"
    "launch-as-broker"
    "launch-as-broker.exe"
)
configure_launch_as_version_resource(
    LauncherAdminVersion.rc
    "launch-as broker administration"
    "launch-as-admin"
    "launch-as-admin.exe"
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
    src/BrokerControlPipe.cpp
    src/BrokerControlPipe.h
    src/BrokerControlClient.cpp
    src/BrokerControlClient.h
    src/BrokerProtocol.cpp
    src/BrokerProtocol.h
    src/launch_as.cpp
    src/LauncherOptions.cpp
    src/LauncherOptions.h
    src/LaunchProcess.cpp
    src/LaunchProcess.h
    src/LicenseHeader.cpp
    src/LicenseHeader.h
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
function(configure_launch_as_target target)
    if(ARGN)
        target_include_directories(${target} PRIVATE ${ARGN})
    endif()

    target_compile_features(${target} PRIVATE cxx_std_23)

    if(MSVC)
        target_compile_options(${target} PRIVATE
            /std:c++latest
            /W4
            /WX
            /EHsc
            /permissive-
            /sdl
            /guard:cf
            /Qspectre
            /utf-8
            /MP
        )
        target_link_options(${target} PRIVATE
            /guard:cf
            /CETCOMPAT
            /DEPENDENTLOADFLAG:0x800
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
        "$<$<NOT:$<CONFIG:Debug>>:NDEBUG>"
    )

    set_target_properties(${target} PROPERTIES
        CXX_EXTENSIONS OFF
    )
endfunction()

target_link_libraries(launch_as PRIVATE
    Advapi32
    Ole32
)
if(MSVC)
    target_link_options(launch_as PRIVATE
        "/MANIFESTINPUT:${CMAKE_CURRENT_BINARY_DIR}/Launcher.manifest"
    )
endif()

configure_launch_as_target(launch_as "${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(launch_as PROPERTIES
    OUTPUT_NAME "launch-as"
)

add_executable(launch_as_conhost
    src/LicenseHeader.cpp
    src/LicenseHeader.h
    src/launch_as_conhost.cpp
    src/LauncherOptions.h
    src/PseudoConsoleHost.cpp
    src/PseudoConsoleHost.h
    src/PseudoConsoleHostReport.h
    src/PseudoConsoleSession.cpp
    src/PseudoConsoleSession.h
    src/TerminalIO.cpp
    src/TerminalIO.h
    src/Win32Support.cpp
    src/Win32Support.h
    src/WindowsCommandLine.cpp
    src/WindowsCommandLine.h
    "${CMAKE_CURRENT_BINARY_DIR}/LauncherConhostVersion.rc"
)
target_link_libraries(launch_as_conhost PRIVATE
    Ole32
)
configure_launch_as_target(launch_as_conhost "${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(launch_as_conhost PROPERTIES
    OUTPUT_NAME "launch-as-conhost"
)

add_executable(launch_as_broker
    src/BrokerAccountProvisioner.cpp
    src/BrokerAccountProvisioner.h
    src/BrokerAudit.cpp
    src/BrokerAudit.h
    src/BrokerCallerPolicy.cpp
    src/BrokerCallerPolicy.h
    src/BrokerControlPipe.cpp
    src/BrokerControlPipe.h
    src/BrokerDataDirectory.cpp
    src/BrokerDataDirectory.h
    src/BrokerEnrollmentStore.cpp
    src/BrokerEnrollmentStore.h
    src/BrokerLogonToken.cpp
    src/BrokerLogonToken.h
    src/BrokerPassword.cpp
    src/BrokerPassword.h
    src/LicenseHeader.cpp
    src/LicenseHeader.h
    src/BrokerProcessLauncher.cpp
    src/BrokerProcessLauncher.h
    src/PseudoConsoleHostReport.h
    src/BrokerRegistration.cpp
    src/BrokerRegistration.h
    src/BrokerPipeServer.cpp
    src/BrokerPipeServer.h
    src/BrokerProtocol.cpp
    src/BrokerProtocol.h
    src/BrokerService.cpp
    src/BrokerServiceRuntime.cpp
    src/BrokerServiceRuntime.h
    src/Win32Support.cpp
    src/Win32Support.h
    src/WindowsCommandLine.cpp
    src/WindowsCommandLine.h
    "${CMAKE_CURRENT_BINARY_DIR}/LauncherBrokerVersion.rc"
)
target_link_libraries(launch_as_broker PRIVATE
    Advapi32
    Bcrypt
    Netapi32
    Ole32
    Shell32
    Userenv
)
configure_launch_as_target(launch_as_broker "${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(launch_as_broker PROPERTIES
    OUTPUT_NAME "launch-as-broker"
)

add_executable(launch_as_admin
    src/BrokerAccountProvisioner.cpp
    src/BrokerAccountProvisioner.h
    src/BrokerAdmin.cpp
    src/BrokerAdminCli.cpp
    src/BrokerAdminCli.h
    src/BrokerAudit.cpp
    src/BrokerAudit.h
    src/BrokerCallerPolicy.cpp
    src/BrokerCallerPolicy.h
    src/BrokerControlPipe.cpp
    src/BrokerControlPipe.h
    src/BrokerDataDirectory.cpp
    src/BrokerDataDirectory.h
    src/LicenseHeader.cpp
    src/LicenseHeader.h
    src/BrokerProtocol.cpp
    src/BrokerProtocol.h
    src/BrokerServiceInstaller.cpp
    src/BrokerServiceInstaller.h
    src/Win32Support.cpp
    src/Win32Support.h
    "${CMAKE_CURRENT_BINARY_DIR}/LauncherAdminVersion.rc"
)
target_link_libraries(launch_as_admin PRIVATE
    Advapi32
    Bcrypt
    Netapi32
    Ole32
    Shell32
)
configure_launch_as_target(launch_as_admin "${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(launch_as_admin PROPERTIES
    OUTPUT_NAME "launch-as-admin"
)

if(BUILD_TESTING)
    add_executable(LauncherBrokerProtocolTests
        tests/BrokerProtocolTests.cpp
        src/BrokerProtocol.cpp
        src/BrokerProtocol.h
    )
    configure_launch_as_target(LauncherBrokerProtocolTests "${CMAKE_CURRENT_SOURCE_DIR}/src")

    add_test(
        NAME launcher.broker_protocol
        COMMAND "$<TARGET_FILE:LauncherBrokerProtocolTests>"
    )
    set_tests_properties(launcher.broker_protocol PROPERTIES
        LABELS "broker;unit"
    )

    add_executable(LauncherBrokerPipeTests
        tests/BrokerPipeTests.cpp
        src/BrokerProcessLauncher.cpp
        src/BrokerProcessLauncher.h
        src/PseudoConsoleHostReport.h
        src/BrokerPipeServer.cpp
        src/BrokerPipeServer.h
        src/BrokerProtocol.cpp
        src/Win32Support.cpp
        src/WindowsCommandLine.cpp
        src/WindowsCommandLine.h
    )
    target_link_libraries(LauncherBrokerPipeTests PRIVATE
        Advapi32
        Userenv
    )
    configure_launch_as_target(LauncherBrokerPipeTests "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_compile_definitions(LauncherBrokerPipeTests PRIVATE
        LAUNCH_AS_TESTING
    )

    add_test(
        NAME launcher.broker_pipe
        COMMAND "$<TARGET_FILE:LauncherBrokerPipeTests>"
    )
    set_tests_properties(launcher.broker_pipe PROPERTIES
        LABELS "broker;integration"
    )

    add_executable(LauncherBrokerCommandTests
        tests/BrokerCommandTests.cpp
        src/BrokerControlPipe.cpp
        src/BrokerControlPipe.h
        src/BrokerProcessLauncher.cpp
        src/BrokerProcessLauncher.h
        src/PseudoConsoleHostReport.h
        src/BrokerPipeServer.cpp
        src/BrokerPipeServer.h
        src/BrokerProtocol.cpp
        src/BrokerProtocol.h
        src/Win32Support.cpp
        src/WindowsCommandLine.cpp
        src/WindowsCommandLine.h
    )
    target_link_libraries(LauncherBrokerCommandTests PRIVATE
        Advapi32
        Userenv
    )
    configure_launch_as_target(LauncherBrokerCommandTests "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_compile_definitions(LauncherBrokerCommandTests PRIVATE
        LAUNCH_AS_TEST_CONTROL_PIPE
    )

    add_executable(LauncherBrokerAdminTestClient
        src/BrokerAccountProvisioner.cpp
        src/BrokerAccountProvisioner.h
        src/BrokerAdmin.cpp
        src/BrokerAdminCli.cpp
        src/BrokerAdminCli.h
        src/BrokerAudit.cpp
        src/BrokerAudit.h
        src/BrokerCallerPolicy.cpp
        src/BrokerCallerPolicy.h
        src/BrokerControlPipe.cpp
        src/BrokerControlPipe.h
        src/BrokerDataDirectory.cpp
        src/BrokerDataDirectory.h
        src/LicenseHeader.cpp
        src/LicenseHeader.h
        src/BrokerProtocol.cpp
        src/BrokerProtocol.h
        src/BrokerServiceInstaller.cpp
        src/BrokerServiceInstaller.h
        src/Win32Support.cpp
        src/Win32Support.h
    )
target_link_libraries(LauncherBrokerAdminTestClient PRIVATE
    Advapi32
    Bcrypt
    Netapi32
        Ole32
        Shell32
    )
    configure_launch_as_target(LauncherBrokerAdminTestClient "${CMAKE_CURRENT_BINARY_DIR}")
    target_compile_definitions(LauncherBrokerAdminTestClient PRIVATE
        LAUNCH_AS_TEST_CONTROL_PIPE
    )
    set_target_properties(LauncherBrokerAdminTestClient PROPERTIES
        OUTPUT_NAME "launch-as-admin-test"
    )

    add_test(
        NAME launcher.broker_command
        COMMAND
            "$<TARGET_FILE:LauncherBrokerCommandTests>"
            "$<TARGET_FILE:LauncherBrokerAdminTestClient>"
            "$<TARGET_FILE:launch_as_broker>"
    )
    set_tests_properties(launcher.broker_command PROPERTIES
        LABELS "broker;integration"
        TIMEOUT 15
    )

    add_test(
        NAME launcher.setup_script
        COMMAND
            pwsh
            -NoProfile
            -File
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/Test-PowerShellSyntax.ps1"
            -Path
            "${CMAKE_CURRENT_SOURCE_DIR}/Setup-LaunchAs.ps1"
    )
    set_tests_properties(launcher.setup_script PROPERTIES
        LABELS "setup;unit"
    )

    add_test(
        NAME launcher.setup_elevation_contract
        COMMAND
            pwsh
            -NoProfile
            -File
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/Test-SetupElevationContract.ps1"
            -Path
            "${CMAKE_CURRENT_SOURCE_DIR}/Setup-LaunchAs.ps1"
    )
    set_tests_properties(launcher.setup_elevation_contract PROPERTIES
        LABELS "setup;unit"
    )

    add_test(
        NAME launcher.setup_update_contract
        COMMAND
            pwsh
            -NoProfile
            -File
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/Test-SetupUpdateContract.ps1"
            -Path
            "${CMAKE_CURRENT_SOURCE_DIR}/Setup-LaunchAs.ps1"
    )
    set_tests_properties(launcher.setup_update_contract PROPERTIES
        LABELS "setup;unit"
    )

    add_test(
        NAME launcher.build_all_tests_contract
        COMMAND
            pwsh
            -NoProfile
            -File
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/Test-BuildAllTestsContract.ps1"
            -Path
            "${CMAKE_CURRENT_SOURCE_DIR}/build.ps1"
    )
    set_tests_properties(launcher.build_all_tests_contract PROPERTIES
        LABELS "build;unit"
    )

    add_test(
        NAME launcher.package_release_contract
        COMMAND
            pwsh
            -NoProfile
            -File
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/Test-PackageReleaseContract.ps1"
            -Path
            "${CMAKE_CURRENT_SOURCE_DIR}/build.ps1"
    )
    set_tests_properties(launcher.package_release_contract PROPERTIES
        LABELS "build;unit"
    )

    add_executable(LauncherBrokerPasswordTests
        tests/BrokerPasswordTests.cpp
        src/BrokerPassword.cpp
        src/BrokerPassword.h
    )
    target_link_libraries(LauncherBrokerPasswordTests PRIVATE
        Bcrypt
    )
    configure_launch_as_target(LauncherBrokerPasswordTests "${CMAKE_CURRENT_SOURCE_DIR}/src")

    add_test(
        NAME launcher.broker_password
        COMMAND "$<TARGET_FILE:LauncherBrokerPasswordTests>"
    )
    set_tests_properties(launcher.broker_password PROPERTIES
        LABELS "broker;unit"
    )

    add_executable(LauncherBrokerEnrollmentStoreTests
        tests/BrokerEnrollmentStoreTests.cpp
        src/BrokerAccountProvisioner.cpp
        src/BrokerAccountProvisioner.h
        src/BrokerEnrollmentStore.cpp
        src/BrokerEnrollmentStore.h
        src/BrokerPassword.cpp
        src/BrokerPassword.h
    )
    target_link_libraries(LauncherBrokerEnrollmentStoreTests PRIVATE
        Bcrypt
        Netapi32
    )
    configure_launch_as_target(LauncherBrokerEnrollmentStoreTests "${CMAKE_CURRENT_SOURCE_DIR}/src")

    add_test(
        NAME launcher.broker_enrollment_store
        COMMAND "$<TARGET_FILE:LauncherBrokerEnrollmentStoreTests>"
    )
    set_tests_properties(launcher.broker_enrollment_store PROPERTIES
        LABELS "broker;unit"
    )

    add_executable(LauncherBrokerDataDirectoryTests
        tests/BrokerDataDirectoryTests.cpp
        src/BrokerDataDirectory.cpp
        src/BrokerDataDirectory.h
    )
    target_link_libraries(LauncherBrokerDataDirectoryTests PRIVATE
        Advapi32
        Ole32
        Shell32
    )
    configure_launch_as_target(LauncherBrokerDataDirectoryTests "${CMAKE_CURRENT_SOURCE_DIR}/src")

    add_test(
        NAME launcher.broker_data_directory
        COMMAND "$<TARGET_FILE:LauncherBrokerDataDirectoryTests>"
    )
    set_tests_properties(launcher.broker_data_directory PROPERTIES
        LABELS "broker;integration"
    )

    add_executable(LauncherBrokerCallerPolicyTests
        tests/BrokerCallerPolicyTests.cpp
        src/BrokerCallerPolicy.cpp
        src/BrokerCallerPolicy.h
    )
    target_link_libraries(LauncherBrokerCallerPolicyTests PRIVATE
        Advapi32
    )
    configure_launch_as_target(LauncherBrokerCallerPolicyTests "${CMAKE_CURRENT_SOURCE_DIR}/src")

    add_test(
        NAME launcher.broker_caller_policy
        COMMAND "$<TARGET_FILE:LauncherBrokerCallerPolicyTests>"
    )
    set_tests_properties(launcher.broker_caller_policy PROPERTIES
        LABELS "broker;integration"
    )

    add_executable(LauncherBrokerProcessLauncherTests
        tests/BrokerProcessLauncherTests.cpp
        src/BrokerProcessLauncher.cpp
        src/BrokerProcessLauncher.h
        src/WindowsCommandLine.cpp
        src/WindowsCommandLine.h
    )
    target_link_libraries(LauncherBrokerProcessLauncherTests PRIVATE
        Advapi32
        Userenv
    )
    configure_launch_as_target(LauncherBrokerProcessLauncherTests "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_compile_definitions(LauncherBrokerProcessLauncherTests PRIVATE
        LAUNCH_AS_TESTING
    )

    add_test(
        NAME launcher.broker_process_launcher
        COMMAND "$<TARGET_FILE:LauncherBrokerProcessLauncherTests>"
    )
    set_tests_properties(launcher.broker_process_launcher PROPERTIES
        LABELS "broker;integration"
    )

    add_executable(LauncherBrokerAuditTests
        tests/BrokerAuditTests.cpp
        src/BrokerAudit.cpp
        src/BrokerAudit.h
    )
    target_link_libraries(LauncherBrokerAuditTests PRIVATE
        Advapi32
    )
    configure_launch_as_target(LauncherBrokerAuditTests "${CMAKE_CURRENT_SOURCE_DIR}/src")

    add_test(
        NAME launcher.broker_audit
        COMMAND "$<TARGET_FILE:LauncherBrokerAuditTests>"
    )
    set_tests_properties(launcher.broker_audit PROPERTIES
        LABELS "broker;elevated;integration"
    )

    add_executable(LauncherBrokerProcessAccessProbe
        tests/BrokerProcessAccessProbe.cpp
    )
    configure_launch_as_target(LauncherBrokerProcessAccessProbe)

    add_executable(LauncherBrokerChildIdentityProbe
        tests/BrokerChildIdentityProbe.cpp
    )
    configure_launch_as_target(LauncherBrokerChildIdentityProbe "${CMAKE_CURRENT_SOURCE_DIR}/src")

    add_executable(LauncherBrokerChildIdentityProbeTests
        tests/BrokerChildIdentityProbeTests.cpp
        src/Win32Support.cpp
        src/Win32Support.h
        src/WindowsCommandLine.cpp
        src/WindowsCommandLine.h
    )
    target_link_libraries(LauncherBrokerChildIdentityProbeTests PRIVATE
        Advapi32
    )
    configure_launch_as_target(LauncherBrokerChildIdentityProbeTests "${CMAKE_CURRENT_SOURCE_DIR}/src")

    add_test(
        NAME launcher.broker_child_identity_probe
        COMMAND
            "$<TARGET_FILE:LauncherBrokerChildIdentityProbeTests>"
            "$<TARGET_FILE:LauncherBrokerChildIdentityProbe>"
    )
    set_tests_properties(launcher.broker_child_identity_probe PROPERTIES
        LABELS "broker;integration"
    )

    add_executable(LauncherBrokerAccountProvisioningTests
        tests/BrokerAccountProvisioningTests.cpp
        src/BrokerAccountProvisioner.cpp
        src/BrokerAccountProvisioner.h
        src/BrokerEnrollmentStore.cpp
        src/BrokerEnrollmentStore.h
        src/BrokerLogonToken.cpp
        src/BrokerLogonToken.h
        src/BrokerPassword.cpp
        src/BrokerPassword.h
        src/BrokerRegistration.cpp
        src/BrokerRegistration.h
    )
    target_link_libraries(LauncherBrokerAccountProvisioningTests PRIVATE
        Bcrypt
        Netapi32
        Advapi32
    )
    configure_launch_as_target(LauncherBrokerAccountProvisioningTests "${CMAKE_CURRENT_SOURCE_DIR}/src")

    add_test(
        NAME launcher.broker_account_provisioning
        COMMAND "$<TARGET_FILE:LauncherBrokerAccountProvisioningTests>"
    )
    set_tests_properties(launcher.broker_account_provisioning PROPERTIES
        LABELS "broker;elevated;integration"
    )

    add_executable(LauncherBrokerServiceInstallerTests
        tests/BrokerServiceInstallerTests.cpp
        src/BrokerAudit.cpp
        src/BrokerAudit.h
        src/BrokerCallerPolicy.cpp
        src/BrokerCallerPolicy.h
        src/BrokerDataDirectory.cpp
        src/BrokerDataDirectory.h
        src/BrokerServiceInstaller.cpp
        src/BrokerServiceInstaller.h
    )
    target_link_libraries(LauncherBrokerServiceInstallerTests PRIVATE
        Advapi32
        Ole32
        Shell32
    )
    configure_launch_as_target(LauncherBrokerServiceInstallerTests "${CMAKE_CURRENT_SOURCE_DIR}/src")

    add_test(
        NAME launcher.broker_install_files
        COMMAND "$<TARGET_FILE:LauncherBrokerServiceInstallerTests>" --files
    )
    set_tests_properties(launcher.broker_install_files PROPERTIES
        LABELS "broker;integration"
    )

    add_test(
        NAME launcher.broker_service_installer
        COMMAND
            "$<TARGET_FILE:LauncherBrokerServiceInstallerTests>"
            "$<TARGET_FILE:launch_as_broker>"
    )
    set_tests_properties(launcher.broker_service_installer PROPERTIES
        LABELS "broker;elevated;integration"
        SKIP_RETURN_CODE 77
    )

    add_executable(LauncherArgvProbe
        tests/ArgvProbe.cpp
    )
    configure_launch_as_target(LauncherArgvProbe)

    add_executable(LauncherTerminalSizeProbe
        tests/TerminalSizeProbe.cpp
    )
    configure_launch_as_target(LauncherTerminalSizeProbe)

    add_executable(LauncherExitCodeProbe
        tests/ExitCodeProbe.cpp
    )
    configure_launch_as_target(LauncherExitCodeProbe)

    add_executable(LauncherCommandLineTests
        tests/CommandLineTests.cpp
        src/WindowsCommandLine.cpp
    )
    configure_launch_as_target(LauncherCommandLineTests
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests"
    )

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

    add_executable(LauncherBinaryMitigationTests
        tests/BinaryMitigationTests.cpp
    )
    configure_launch_as_target(LauncherBinaryMitigationTests)

    add_test(
        NAME launcher.binary_mitigations
        COMMAND
            "$<TARGET_FILE:LauncherBinaryMitigationTests>"
            "$<TARGET_FILE:launch_as>"
    )
    set_tests_properties(launcher.binary_mitigations PROPERTIES
        LABELS "launcher;unit"
    )

    add_executable(LauncherPseudoConsoleTests
        tests/PseudoConsoleTests.cpp
        src/TerminalBridge.cpp
        src/TerminalIO.cpp
        src/Win32Support.cpp
        src/WindowsCommandLine.cpp
    )
    configure_launch_as_target(LauncherPseudoConsoleTests "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(LauncherPseudoConsoleTests PRIVATE
        Advapi32
        Ole32
    )

    add_test(
        NAME launcher.pseudoconsole
        COMMAND
            "$<TARGET_FILE:LauncherPseudoConsoleTests>"
            "$<TARGET_FILE:launch_as_conhost>"
            "$<TARGET_FILE:LauncherTerminalSizeProbe>"
    )
    set_tests_properties(launcher.pseudoconsole PROPERTIES
        LABELS "launcher;integration;terminal"
        PASS_REGULAR_EXPRESSION "conpty-smoke-256"
        TIMEOUT 15
    )

    add_executable(LauncherBrokerTerminalBridgeTests
        tests/BrokerTerminalBridgeTests.cpp
        src/TerminalBridge.cpp
        src/TerminalBridge.h
        src/TerminalIO.cpp
        src/TerminalIO.h
        src/Win32Support.cpp
        src/Win32Support.h
        src/WindowsCommandLine.cpp
        src/WindowsCommandLine.h
    )
    target_link_libraries(LauncherBrokerTerminalBridgeTests PRIVATE
        Advapi32
        Ole32
    )
    configure_launch_as_target(LauncherBrokerTerminalBridgeTests "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_compile_definitions(LauncherBrokerTerminalBridgeTests PRIVATE
        LAUNCH_AS_TESTING
    )

    add_test(
        NAME launcher.broker_terminal_bridge
        COMMAND "$<TARGET_FILE:LauncherBrokerTerminalBridgeTests>" "$<TARGET_FILE:launch_as_conhost>"
    )
    set_tests_properties(launcher.broker_terminal_bridge PROPERTIES
        LABELS "broker;integration"
        SKIP_RETURN_CODE 77
        TIMEOUT 30
    )

    add_executable(LauncherTerminalDisconnectTests
        tests/TerminalDisconnectTests.cpp
        src/TerminalBridge.cpp
        src/TerminalIO.cpp
        src/Win32Support.cpp
        src/WindowsCommandLine.cpp
    )
    configure_launch_as_target(LauncherTerminalDisconnectTests "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(LauncherTerminalDisconnectTests PRIVATE
        Advapi32
        Ole32
    )

    add_test(
        NAME launcher.terminal_disconnect
        COMMAND
            "$<TARGET_FILE:LauncherTerminalDisconnectTests>"
            "$<TARGET_FILE:launch_as_conhost>"
            "$<TARGET_FILE:LauncherExitCodeProbe>"
    )
    set_tests_properties(launcher.terminal_disconnect PROPERTIES
        LABELS "launcher;integration;terminal"
        PASS_REGULAR_EXPRESSION "Redirected stdin EOF preserved the helper exit code"
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
            -BrokerPath
            "$<TARGET_FILE:launch_as_broker>"
            -AdminPath
            "$<TARGET_FILE:launch_as_admin>"
            -ConhostPath
            "$<TARGET_FILE:launch_as_conhost>"
            -ExpectedVersion
            "${LAUNCH_AS_VERSION}"
    )
    set_tests_properties(launcher.behavior PROPERTIES
        LABELS "launcher;behavior"
    )

endif()
