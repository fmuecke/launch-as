# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: MIT
# Part of claude-win-sandbox: https://github.com/fmuecke/claude-win-sandbox

configure_file(
    resources/LauncherVersion.rc.in
    "${CMAKE_CURRENT_BINARY_DIR}/LauncherVersion.rc"
    @ONLY
)

add_executable(ClaudeSandboxLauncher
    src/CredentialInput.cpp
    src/CredentialInput.h
    src/Credentials.cpp
    src/Credentials.h
    src/ClaudeSandboxLauncher.cpp
    src/LauncherOptions.cpp
    src/LauncherOptions.h
    src/PseudoConsoleHost.cpp
    src/PseudoConsoleHost.h
    src/PseudoConsoleSession.cpp
    src/PseudoConsoleSession.h
    src/SandboxProcess.cpp
    src/SandboxProcess.h
    src/TerminalBridge.cpp
    src/TerminalBridge.h
    src/Win32Support.cpp
    src/Win32Support.h
    src/WindowsCommandLine.cpp
    src/WindowsCommandLine.h
    "${CMAKE_CURRENT_BINARY_DIR}/LauncherVersion.rc"
)

function(configure_native_target target)
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
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"
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

target_link_libraries(ClaudeSandboxLauncher PRIVATE
    Advapi32
    Credui
    Ole32
)

configure_native_target(ClaudeSandboxLauncher)

if(BUILD_TESTING)
    add_executable(LauncherArgvProbe
        tests/ArgvProbe.cpp
    )
    configure_native_target(LauncherArgvProbe)

    add_executable(LauncherCommandLineTests
        tests/CommandLineTests.cpp
        src/WindowsCommandLine.cpp
    )
    target_include_directories(LauncherCommandLineTests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests"
    )
    configure_native_target(LauncherCommandLineTests)

    add_test(
        NAME launcher.command_line
        COMMAND
            "$<TARGET_FILE:LauncherCommandLineTests>"
            "$<TARGET_FILE:LauncherArgvProbe>"
    )
    set_tests_properties(launcher.command_line PROPERTIES
        LABELS "launcher;unit"
    )

    add_executable(LauncherPseudoConsoleTests
        tests/PseudoConsoleTests.cpp
        src/TerminalBridge.cpp
        src/Win32Support.cpp
        src/WindowsCommandLine.cpp
    )
    target_include_directories(LauncherPseudoConsoleTests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
    )
    configure_native_target(LauncherPseudoConsoleTests)
    target_link_libraries(LauncherPseudoConsoleTests PRIVATE
        Advapi32
        Ole32
    )

    add_test(
        NAME launcher.pseudoconsole
        COMMAND
            "$<TARGET_FILE:LauncherPseudoConsoleTests>"
            "$<TARGET_FILE:ClaudeSandboxLauncher>"
    )
    set_tests_properties(launcher.pseudoconsole PROPERTIES
        LABELS "launcher;integration;terminal"
        PASS_REGULAR_EXPRESSION "conpty-smoke-256"
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
            "$<TARGET_FILE:ClaudeSandboxLauncher>"
            -ExpectedVersion
            "${PROJECT_VERSION}"
            -ExpectedTestCredentialTagVisibility
            "$<IF:$<CONFIG:Debug>,Visible,Hidden>"
    )
    set_tests_properties(launcher.behavior PROPERTIES
        LABELS "launcher;behavior"
    )

    add_test(
        NAME launcher.version_consistency
        COMMAND
            "${POWERSHELL_EXECUTABLE}"
            -NoLogo
            -NoProfile
            -NonInteractive
            -ExecutionPolicy Bypass
            -File
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/Test-ProjectVersion.ps1"
            -RepoRoot
            "${PROJECT_SOURCE_DIR}"
            -ExpectedVersion
            "${PROJECT_VERSION}"
    )
    set_tests_properties(launcher.version_consistency PROPERTIES
        LABELS "launcher;version"
    )
endif()
