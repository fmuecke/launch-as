# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

cmake_minimum_required(VERSION 3.25)

project(
    launch_as
    VERSION 1.2.0
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

function(configure_launch_as_target target)
    target_include_directories(${target} PRIVATE
        ${ARGN}
    )

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

function(configure_launch_as_module target source_directory)
    configure_launch_as_target(${target})
    target_include_directories(${target} PUBLIC
        "$<BUILD_INTERFACE:${source_directory}>"
    )
endfunction()

function(configure_launch_as_test_target target)
    configure_launch_as_target(${target})
    target_include_directories(${target} PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests"
    )
    foreach(module IN LISTS ARGN)
        target_include_directories(${target} PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src/${module}"
        )
    endforeach()
endfunction()

add_subdirectory(src/common)
add_subdirectory(src/protocol)
add_subdirectory(src/terminal)
add_subdirectory(src/launcher)
add_subdirectory(src/conhost)
add_subdirectory(src/broker)
add_subdirectory(src/admin)

add_executable(launch_as
    src/launcher/launch_as.cpp
    "${CMAKE_CURRENT_BINARY_DIR}/LauncherVersion.rc"
)
target_link_libraries(launch_as PRIVATE
    launch_as::launcher
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
    src/conhost/launch_as_conhost.cpp
    "${CMAKE_CURRENT_BINARY_DIR}/LauncherConhostVersion.rc"
)
target_link_libraries(launch_as_conhost PRIVATE
    launch_as::conhost
    Ole32
)
configure_launch_as_target(launch_as_conhost "${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(launch_as_conhost PROPERTIES
    OUTPUT_NAME "launch-as-conhost"
)

add_executable(launch_as_broker
    src/broker/BrokerService.cpp
    "${CMAKE_CURRENT_BINARY_DIR}/LauncherBrokerVersion.rc"
)
target_link_libraries(launch_as_broker PRIVATE
    launch_as::broker
    launch_as::common
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
    src/admin/BrokerAdmin.cpp
    "${CMAKE_CURRENT_BINARY_DIR}/LauncherAdminVersion.rc"
)
target_link_libraries(launch_as_admin PRIVATE
    launch_as::admin
    launch_as::common
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
        src/protocol/BrokerProtocol.cpp
        src/protocol/BrokerProtocol.h
    )
    configure_launch_as_test_target(LauncherBrokerProtocolTests protocol common)

    add_test(
        NAME launcher.broker_protocol
        COMMAND "$<TARGET_FILE:LauncherBrokerProtocolTests>"
    )
    set_tests_properties(launcher.broker_protocol PROPERTIES
        LABELS "broker;unit"
    )

    add_executable(LauncherBrokerPipeTests
        tests/BrokerPipeTests.cpp
        src/broker/BrokerProcessLauncher.cpp
        src/broker/BrokerProcessLauncher.h
        src/protocol/PseudoConsoleHostReport.h
        src/broker/BrokerPipeServer.cpp
        src/broker/BrokerPipeServer.h
        src/protocol/BrokerProtocol.cpp
        src/common/Win32Support.cpp
        src/common/WindowsCommandLine.cpp
        src/common/WindowsCommandLine.h
    )
    target_link_libraries(LauncherBrokerPipeTests PRIVATE
        Advapi32
        Userenv
    )
    configure_launch_as_test_target(LauncherBrokerPipeTests broker protocol common)
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
        src/protocol/BrokerControlPipe.cpp
        src/protocol/BrokerControlPipe.h
        src/broker/BrokerProcessLauncher.cpp
        src/broker/BrokerProcessLauncher.h
        src/protocol/PseudoConsoleHostReport.h
        src/broker/BrokerPipeServer.cpp
        src/broker/BrokerPipeServer.h
        src/protocol/BrokerProtocol.cpp
        src/protocol/BrokerProtocol.h
        src/common/Win32Support.cpp
        src/common/WindowsCommandLine.cpp
        src/common/WindowsCommandLine.h
    )
    target_link_libraries(LauncherBrokerCommandTests PRIVATE
        Advapi32
        Userenv
    )
    configure_launch_as_test_target(LauncherBrokerCommandTests broker protocol common)
    target_compile_definitions(LauncherBrokerCommandTests PRIVATE
        LAUNCH_AS_TEST_CONTROL_PIPE
    )

    add_executable(LauncherBrokerAdminTestClient
        src/broker/BrokerAccountProvisioner.cpp
        src/broker/BrokerAccountProvisioner.h
        src/admin/BrokerAdmin.cpp
        src/admin/BrokerAdminCli.cpp
        src/admin/BrokerAdminCli.h
        src/broker/BrokerAudit.cpp
        src/broker/BrokerAudit.h
        src/broker/BrokerCallerPolicy.cpp
        src/broker/BrokerCallerPolicy.h
        src/protocol/BrokerControlPipe.cpp
        src/protocol/BrokerControlPipe.h
        src/broker/BrokerDataDirectory.cpp
        src/broker/BrokerDataDirectory.h
        src/common/LicenseHeader.cpp
        src/common/LicenseHeader.h
        src/protocol/BrokerProtocol.cpp
        src/protocol/BrokerProtocol.h
        src/admin/BrokerServiceInstaller.cpp
        src/admin/BrokerServiceInstaller.h
        src/common/Win32Support.cpp
        src/common/Win32Support.h
    )
target_link_libraries(LauncherBrokerAdminTestClient PRIVATE
    Advapi32
    Bcrypt
    Netapi32
        Ole32
        Shell32
    )
    configure_launch_as_test_target(
        LauncherBrokerAdminTestClient admin broker protocol common)
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
        NAME launcher.sandbox_integration_contract
        COMMAND
            pwsh
            -NoProfile
            -File
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/Test-SandboxIntegrationContract.ps1"
            -Path
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/Invoke-BrokerIntegrationInWindowsSandbox.ps1"
    )
    set_tests_properties(launcher.sandbox_integration_contract PROPERTIES
        LABELS "build;unit"
    )

    add_test(
        NAME launcher.interactive_session_probe_contract
        COMMAND
            pwsh
            -NoProfile
            -File
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/Test-InteractiveSessionProbeContract.ps1"
            -RunnerPath
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/Invoke-InteractiveSessionProbeInWindowsSandbox.ps1"
            -DriverPath
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/Run-InteractiveSessionProbeInSandbox.ps1"
    )
    set_tests_properties(launcher.interactive_session_probe_contract PROPERTIES
        LABELS "build;unit"
    )

    add_test(
        NAME launcher.test_isolation_contract
        COMMAND
            pwsh
            -NoProfile
            -File
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/Test-TestIsolationContract.ps1"
            -CMakePath
            "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
            -AcceptanceScriptDirectory
            "${CMAKE_CURRENT_SOURCE_DIR}/tests"
    )
    set_tests_properties(launcher.test_isolation_contract PROPERTIES
        LABELS "build;unit"
    )

    add_test(
        NAME launcher.sandbox_acceptance_contract
        COMMAND
            pwsh
            -NoProfile
            -File
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/Test-SandboxAcceptanceContract.ps1"
            -RunnerPath
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/Invoke-LauncherAcceptanceInWindowsSandbox.ps1"
            -DriverPath
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/Run-LauncherAcceptanceInSandbox.ps1"
            -FixturePath
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/Install-LauncherAcceptanceFixture.ps1"
            -DemandStartPath
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/Invoke-BrokerDemandStartTest.ps1"
            -LogonHelperPath
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/LauncherAcceptanceLogon.cs"
            -SupportModulePath
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/WindowsSandboxAcceptanceSupport.psm1"
            -StandardCallerPath
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/Invoke-LauncherAcceptanceAsStandardUser.ps1"
            -AcceptancePath
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/Invoke-LauncherAcceptanceTest.ps1"
            -ConcurrencyPath
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/Invoke-BrokerSameAccountConcurrencyTest.ps1"
    )
    set_tests_properties(launcher.sandbox_acceptance_contract PROPERTIES
        LABELS "build;unit"
    )

    add_test(
        NAME launcher.acceptance_logon_compilation
        COMMAND
            powershell.exe
            -NoProfile
            -File
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/Test-CSharpCompilation.ps1"
            -Path
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/LauncherAcceptanceLogon.cs"
            -TypeName
            "LaunchAs.AcceptanceLogonV2"
    )
    set_tests_properties(launcher.acceptance_logon_compilation PROPERTIES
        LABELS "build;unit"
    )

    foreach(script_name IN ITEMS
            Install-LauncherAcceptanceFixture.ps1
            Invoke-BrokerDemandStartTest.ps1
            Invoke-InteractiveSessionProbeInWindowsSandbox.ps1
            Invoke-LauncherAcceptanceAsStandardUser.ps1
            Run-LauncherAcceptanceInSandbox.ps1
            Show-LauncherAcceptanceWindow.ps1
            Invoke-LauncherAcceptanceInWindowsSandbox.ps1
            Invoke-LauncherAcceptanceTest.ps1
            Invoke-BrokerConsoleAcceptanceTest.ps1
            Invoke-BrokerProbeAcceptanceTest.ps1
            Invoke-BrokerSameAccountConcurrencyTest.ps1
            Run-InteractiveSessionProbeInSandbox.ps1
            WindowsSandboxAcceptanceSupport.psm1)
        string(REGEX REPLACE "\\.psm?1$" "" script_test_name "${script_name}")
        string(TOLOWER "${script_test_name}" script_test_name)
        add_test(
            NAME "launcher.${script_test_name}_syntax"
            COMMAND
                powershell.exe
                -NoProfile
                -File
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/Test-PowerShellSyntax.ps1"
                -Path
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/${script_name}"
        )
        set_tests_properties("launcher.${script_test_name}_syntax" PROPERTIES
            LABELS "build;unit"
        )
    endforeach()

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
        src/broker/BrokerPassword.cpp
        src/broker/BrokerPassword.h
    )
    target_link_libraries(LauncherBrokerPasswordTests PRIVATE
        Bcrypt
    )
    configure_launch_as_test_target(LauncherBrokerPasswordTests broker)

    add_test(
        NAME launcher.broker_password
        COMMAND "$<TARGET_FILE:LauncherBrokerPasswordTests>"
    )
    set_tests_properties(launcher.broker_password PROPERTIES
        LABELS "broker;unit"
    )

    add_executable(LauncherBrokerEnrollmentStoreTests
        tests/BrokerEnrollmentStoreTests.cpp
        src/broker/BrokerAccountProvisioner.cpp
        src/broker/BrokerAccountProvisioner.h
        src/broker/BrokerEnrollmentStore.cpp
        src/broker/BrokerEnrollmentStore.h
        src/broker/BrokerPassword.cpp
        src/broker/BrokerPassword.h
    )
    target_link_libraries(LauncherBrokerEnrollmentStoreTests PRIVATE
        Bcrypt
        Netapi32
    )
    configure_launch_as_test_target(LauncherBrokerEnrollmentStoreTests broker)

    add_test(
        NAME launcher.broker_enrollment_store
        COMMAND "$<TARGET_FILE:LauncherBrokerEnrollmentStoreTests>"
    )
    set_tests_properties(launcher.broker_enrollment_store PROPERTIES
        LABELS "broker;unit"
    )

    add_executable(LauncherBrokerDataDirectoryTests
        tests/BrokerDataDirectoryTests.cpp
        src/broker/BrokerDataDirectory.cpp
        src/broker/BrokerDataDirectory.h
    )
    target_link_libraries(LauncherBrokerDataDirectoryTests PRIVATE
        Advapi32
        Ole32
        Shell32
    )
    configure_launch_as_test_target(LauncherBrokerDataDirectoryTests broker common)

    add_test(
        NAME launcher.broker_data_directory
        COMMAND "$<TARGET_FILE:LauncherBrokerDataDirectoryTests>"
    )
    set_tests_properties(launcher.broker_data_directory PROPERTIES
        LABELS "broker;integration"
    )

    add_executable(LauncherBrokerCallerPolicyTests
        tests/BrokerCallerPolicyTests.cpp
        src/broker/BrokerCallerPolicy.cpp
        src/broker/BrokerCallerPolicy.h
    )
    target_link_libraries(LauncherBrokerCallerPolicyTests PRIVATE
        Advapi32
    )
    configure_launch_as_test_target(LauncherBrokerCallerPolicyTests broker common)

    add_test(
        NAME launcher.broker_caller_policy
        COMMAND "$<TARGET_FILE:LauncherBrokerCallerPolicyTests>"
    )
    set_tests_properties(launcher.broker_caller_policy PROPERTIES
        LABELS "broker;integration"
    )

    add_executable(LauncherBrokerProcessLauncherTests
        tests/BrokerProcessLauncherTests.cpp
        src/broker/BrokerProcessLauncher.cpp
        src/broker/BrokerProcessLauncher.h
        src/common/WindowsCommandLine.cpp
        src/common/WindowsCommandLine.h
    )
    target_link_libraries(LauncherBrokerProcessLauncherTests PRIVATE
        Advapi32
        Userenv
    )
    configure_launch_as_test_target(
        LauncherBrokerProcessLauncherTests broker protocol common)
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
        src/broker/BrokerAudit.cpp
        src/broker/BrokerAudit.h
    )
    target_link_libraries(LauncherBrokerAuditTests PRIVATE
        Advapi32
    )
    configure_launch_as_test_target(LauncherBrokerAuditTests broker)

    add_executable(LauncherBrokerProcessAccessProbe
        tests/BrokerProcessAccessProbe.cpp
    )
    configure_launch_as_target(LauncherBrokerProcessAccessProbe)

    add_executable(LauncherInteractiveSessionProbe
        tests/InteractiveSessionProbe.cpp
    )
    configure_launch_as_target(LauncherInteractiveSessionProbe)

    add_executable(LauncherInteractiveAclLeaseProbe
        tests/InteractiveAclLeaseProbe.cpp
    )
    target_link_libraries(LauncherInteractiveAclLeaseProbe PRIVATE
        Advapi32
        User32
    )
    configure_launch_as_target(LauncherInteractiveAclLeaseProbe)

    add_executable(LauncherBrokerChildIdentityProbe
        tests/BrokerChildIdentityProbe.cpp
    )
    configure_launch_as_test_target(LauncherBrokerChildIdentityProbe common)

    add_executable(LauncherBrokerChildIdentityProbeTests
        tests/BrokerChildIdentityProbeTests.cpp
        src/common/Win32Support.cpp
        src/common/Win32Support.h
        src/common/WindowsCommandLine.cpp
        src/common/WindowsCommandLine.h
    )
    target_link_libraries(LauncherBrokerChildIdentityProbeTests PRIVATE
        Advapi32
    )
    configure_launch_as_test_target(LauncherBrokerChildIdentityProbeTests common)

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
        src/broker/BrokerAccountProvisioner.cpp
        src/broker/BrokerAccountProvisioner.h
        src/broker/BrokerEnrollmentStore.cpp
        src/broker/BrokerEnrollmentStore.h
        src/broker/BrokerLogonToken.cpp
        src/broker/BrokerLogonToken.h
        src/broker/BrokerPassword.cpp
        src/broker/BrokerPassword.h
        src/broker/BrokerRegistration.cpp
        src/broker/BrokerRegistration.h
    )
    target_link_libraries(LauncherBrokerAccountProvisioningTests PRIVATE
        Bcrypt
        Netapi32
        Advapi32
    )
    configure_launch_as_test_target(LauncherBrokerAccountProvisioningTests broker common)

    add_executable(LauncherBrokerServiceInstallerTests
        tests/BrokerServiceInstallerTests.cpp
        src/broker/BrokerAudit.cpp
        src/broker/BrokerAudit.h
        src/broker/BrokerCallerPolicy.cpp
        src/broker/BrokerCallerPolicy.h
        src/broker/BrokerDataDirectory.cpp
        src/broker/BrokerDataDirectory.h
        src/admin/BrokerServiceInstaller.cpp
        src/admin/BrokerServiceInstaller.h
    )
    target_link_libraries(LauncherBrokerServiceInstallerTests PRIVATE
        Advapi32
        Ole32
        Shell32
    )
    configure_launch_as_test_target(
        LauncherBrokerServiceInstallerTests admin broker common)

    add_test(
        NAME launcher.broker_install_files
        COMMAND "$<TARGET_FILE:LauncherBrokerServiceInstallerTests>" --files
    )
    set_tests_properties(launcher.broker_install_files PROPERTIES
        LABELS "broker;integration"
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
        src/common/WindowsCommandLine.cpp
    )
    configure_launch_as_test_target(LauncherCommandLineTests common)

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
        src/terminal/TerminalBridge.cpp
        src/terminal/TerminalIO.cpp
        src/common/Win32Support.cpp
        src/common/WindowsCommandLine.cpp
    )
    configure_launch_as_test_target(LauncherPseudoConsoleTests terminal common)
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
        src/terminal/TerminalBridge.cpp
        src/terminal/TerminalBridge.h
        src/terminal/TerminalIO.cpp
        src/terminal/TerminalIO.h
        src/common/Win32Support.cpp
        src/common/Win32Support.h
        src/common/WindowsCommandLine.cpp
        src/common/WindowsCommandLine.h
    )
    target_link_libraries(LauncherBrokerTerminalBridgeTests PRIVATE
        Advapi32
        Ole32
    )
    configure_launch_as_test_target(LauncherBrokerTerminalBridgeTests terminal common)
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
        src/terminal/TerminalBridge.cpp
        src/terminal/TerminalIO.cpp
        src/common/Win32Support.cpp
        src/common/WindowsCommandLine.cpp
    )
    configure_launch_as_test_target(LauncherTerminalDisconnectTests terminal common)
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
