# VGWW - Virtual Gateway for Windows.
# Root build script. Consumes xtcp (userspace TCP stack) as an embedded
# dependency and nlohmann/json for configuration parsing.
#
# Prerequisites:
#   * Visual Studio 2022 (or any C++17 toolchain)
#   * CMake >= 3.20
#   * Network access on first configure (FetchContent downloads deps)
cmake_minimum_required(VERSION 3.20)

project(vgww VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Static CRT everywhere (user mandate: no dynamic runtime, matches the
# x64-windows-static vcpkg triplet): /MT for release, /MTd for debug.
cmake_policy(SET CMP0091 NEW)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if(MSVC)
    # /W4: high warning level. /utf-8: sources are UTF-8 (bilingual docs quote them).
    # /Zi + /DEBUG: keep PDBs so crash dumps map to source lines.
    add_compile_options(/W4 /permissive- /utf-8 /Zi)
    # NOMINMAX: the Windows SDK min/max macros would otherwise rewrite
    # std::min/std::max calls and break compilation.
    add_compile_definitions(NOMINMAX)
    add_link_options(/DEBUG)
else()
    add_compile_options(-Wall -Wextra)
endif()

# ---------------------------------------------------------------------------
# AddressSanitizer (diagnostic builds only; never part of a delivery).
# /MT is supported by the MSVC ASan runtime (verified against
# learn.microsoft.com/cpp/sanitizers/asan-building): since VS 2022 17.7 the
# runtime ships as clang_rt.asan_dynamic-x86_64.dll and must be on PATH when
# running. /RTC1 (CMake's Debug default) and incremental linking are
# incompatible and are disabled here.
# ---------------------------------------------------------------------------
option(VGWW_ASAN "Build with MSVC AddressSanitizer (diagnostic use only)" OFF)
if(VGWW_ASAN)
    if(NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
        message(FATAL_ERROR "VGWW_ASAN requires the MSVC x64 toolchain")
    endif()
    add_compile_options(/fsanitize=address)
    # batch309: ASan instrumentation multiplies the section count; the largest
    # test translation units (test_ui.cpp, 33k lines) exceed the default
    # object-file limit (C1128). /bigobj is harmless for every other target
    # and keeps the diagnostic build complete.
    add_compile_options(/bigobj)
    # The ASan runtime libraries are linked automatically (link.exe's
    # /INFERASANLIBS is ON by default; verified by dumpbin: the exes depend
    # on clang_rt.asan_dynamic-x86_64.dll). Passing /fsanitize=address to
    # link.exe directly only emits LNK4044 (the option is a cl-driver
    # option), so only the incremental-link incompatibility is set here.
    add_link_options(/INCREMENTAL:NO)
    string(REPLACE "/RTC1" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
    message(STATUS "AddressSanitizer enabled (diagnostic build)")
endif()

option(VGWW_BUILD_TESTS "Build VGWW unit tests" ON)
option(VGWW_JEMALLOC "Use jemalloc as the process-wide memory backend" ON)
set(VGWW_XTCP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/xtcp" CACHE PATH
    "Path to the xtcp stack checkout (git submodule; see README)")

# jemalloc backend: statically linked from the x64-windows-static vcpkg
# triplet (jemalloc_s.lib, same install the sibling openppp2 project uses).
# No runtime DLL is involved; when the library is missing the build degrades
# to the CRT backend with a warning - never a hard error.
if(VGWW_JEMALLOC)
    set(VGWW_JEMALLOC_HINT "$ENV{VCPKG_ROOT}/installed/x64-windows-static")
    find_path(VGWW_JEMALLOC_INCLUDE_DIR
              NAMES jemalloc/jemalloc.h
              HINTS ${VGWW_JEMALLOC_HINT}/include)
    find_library(VGWW_JEMALLOC_LIB
                 NAMES jemalloc_s
                 HINTS ${VGWW_JEMALLOC_HINT}/lib)
    if(VGWW_JEMALLOC_INCLUDE_DIR AND VGWW_JEMALLOC_LIB)
        # Derive the debug vcpkg static lib from wherever the release lib was
        # found (the triplet keeps it at <root>/debug/lib), so lookup does not
        # depend on $ENV{VCPKG_ROOT} being set at configure time. This derive
        # must stay inside the found-guard: with no vcpkg install present the
        # release lib is empty and get_filename_component on it aborts the
        # configure pass, breaking the documented fallback.
        get_filename_component(VGWW_JEMALLOC_LIB_DIR
                               ${VGWW_JEMALLOC_LIB} DIRECTORY)
        get_filename_component(VGWW_JEMALLOC_ROOT
                               ${VGWW_JEMALLOC_LIB_DIR} DIRECTORY)
        find_library(VGWW_JEMALLOC_LIB_DEBUG
                     NAMES jemalloc_s
                     HINTS ${VGWW_JEMALLOC_ROOT}/debug/lib)
        message(STATUS "jemalloc backend enabled (static): ${VGWW_JEMALLOC_LIB}")
        add_compile_definitions(VGWW_JEMALLOC)
    else()
        message(WARNING "VGWW_JEMALLOC=ON but static jemalloc was not found "
                        "under ${VGWW_JEMALLOC_HINT}; falling back to the CRT backend")
    endif()
endif()

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
include(FetchContent)

FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(nlohmann_json)

# Standalone Asio (no Boost) for upstream sockets / UDP relays / timers.
FetchContent_Declare(
    asio
    URL https://github.com/chriskohlhoff/asio/archive/refs/tags/asio-1-30-2.tar.gz
)
FetchContent_MakeAvailable(asio)
add_library(asio_headers INTERFACE)
target_include_directories(asio_headers INTERFACE ${asio_SOURCE_DIR}/asio/include)
target_compile_definitions(asio_headers INTERFACE ASIO_STANDALONE ASIO_NO_DEPRECATED)
target_link_libraries(asio_headers INTERFACE ws2_32 mswsock)

# xtcp: userspace TCP/IP stack (our own project). Tests/bench are off - VGWW
# carries its own test suite.
set(XTCP_BUILD_TESTS      OFF CACHE BOOL "" FORCE)
set(XTCP_BUILD_BENCH      OFF CACHE BOOL "" FORCE)
set(XTCP_BUILD_PLUGINS    OFF CACHE BOOL "" FORCE)
set(XTCP_CHECKSUM_VALIDATE ON  CACHE BOOL "" FORCE)
add_subdirectory(${VGWW_XTCP_DIR} xtcp_build EXCLUDE_FROM_ALL)

# ---------------------------------------------------------------------------
# VGWW library + executable
# ---------------------------------------------------------------------------
add_library(vgww_core STATIC
    src/bridge/bridge.cpp
    src/core/config.cpp
    src/core/random.cpp
    src/driver/idriver_client.h
    src/driver/error_class.cpp
    src/driver/installer.cpp
    src/driver/ndisrd_client.cpp
    src/dsp/classifier.cpp
    src/proto/arp.cpp
    src/proto/dhcp.cpp
    src/proto/dhcp6.cpp
    src/proto/icmp.cpp
    src/proto/ndp.cpp
    src/relay/icmp_relay.cpp
    src/relay/portmap_manager.cpp
    src/relay/tcp_relay.cpp
    src/relay/udp_relay.cpp
    src/runtime/dataplane.cpp
    src/startup_options.cpp
    src/tables/neighbors.cpp
    src/tables/rate_limiter.cpp
    src/web/http_server.cpp
    src/web/web_api.cpp
)
target_include_directories(vgww_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
    ${VGWW_XTCP_DIR}/include
)
target_link_libraries(vgww_core PUBLIC nlohmann_json::nlohmann_json asio_headers ws2_32 Iphlpapi bcrypt uuid ole32 shell32 winmm)

if(VGWW_JEMALLOC_INCLUDE_DIR AND VGWW_JEMALLOC_LIB)
    target_include_directories(vgww_core PUBLIC ${VGWW_JEMALLOC_INCLUDE_DIR})
    if(MSVC AND VGWW_JEMALLOC_LIB_DEBUG)
        # Link the vcpkg debug static lib in Debug so its CRT (LIBCMTD)
        # matches the target; a Release lib would trigger LNK4098.
        target_link_libraries(vgww_core PUBLIC
            "$<$<CONFIG:Debug>:${VGWW_JEMALLOC_LIB_DEBUG}>"
            "$<$<NOT:$<CONFIG:Debug>>:${VGWW_JEMALLOC_LIB}>")
    else()
        target_link_libraries(vgww_core PUBLIC ${VGWW_JEMALLOC_LIB})
    endif()
endif()

# ---------------------------------------------------------------------------
# Native UI (S4.2). vgww_ui carries the UI; the headless-testable parts
# (theme/format/i18n here; element tree, layout, snapshots, pages later) run
# under test_ui/test_sync without ever creating a window. vgww itself does not
# link vgww_ui yet (no consumer until a later S4 task).
# ---------------------------------------------------------------------------
add_library(vgww_ui STATIC
    src/ui/theme.cpp
    src/ui/format.cpp
    src/ui/i18n.cpp
    src/ui/element.cpp
    src/ui/controls.cpp
    src/ui/snapshot.cpp
    src/ui/controller.cpp
    src/ui/renderer.cpp
    src/ui/window.cpp
    src/ui/tray.cpp
    src/ui/ui_state.cpp
    src/ui/router.cpp
    src/ui/console_log.cpp
    src/ui/pages/page.cpp
    src/ui/pages/page_util.cpp
    src/ui/pages/dashboard.cpp
    src/ui/pages/leases.cpp
    src/ui/pages/portmap.cpp
    src/ui/pages/firewall.cpp
    src/ui/pages/ratelimit.cpp
    src/ui/pages/bridge_page.cpp
    src/ui/pages/settings.cpp
    src/ui/pages/about.cpp
    src/ui/pages/console.cpp
    src/ui/app.cpp
    src/ui/debug/ui_debug_serialize.cpp
    src/ui/debug/ui_debug_controller.cpp
    src/ui/debug/ui_debug_server.cpp
)
target_link_libraries(vgww_ui PUBLIC vgww_core d2d1 dwrite dwmapi shell32 ole32 comctl32 advapi32 imm32)
    # M5: xtcp_static is a private implementation link of vgww_ui
    # (controller.cpp calls runtime::Dataplane, whose object code references
    # the xtcp stack); consumers declare the dependency themselves.
    target_link_libraries(vgww_ui PRIVATE xtcp_static)

add_executable(vgww src/main.cpp src/vgww.rc)
target_link_libraries(vgww PRIVATE vgww_core vgww_ui xtcp_static advapi32)

# Single-file distribution: embed www/index.html into the executable as an
# RCDATA resource so the WebUI ships inside vgww.exe (no www/ folder next to
# the binary). http_server serves the embedded copy first and only falls back
# to the filesystem www/ in dev runs.
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/vgww_webui.rc
    "24001 RCDATA \"${CMAKE_CURRENT_SOURCE_DIR}/www/index.html\"\n")
target_sources(vgww PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/vgww_webui.rc)

# Batch19 R4-P0: embed the generated M1 native language resource (compact
# UTF-8; catalog + per-language blocks). The file is produced by
# scripts/gen-native-i18n.mjs and checked in; i18n.cpp loads one language
# block lazily via FindResource(24002). test_ui embeds the same rc so the
# lazy-loader path is exercised there.
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/ui/i18n_gen.bin")
    message(FATAL_ERROR
        "src/ui/i18n_gen.bin is missing. It is a checked-in generated "
        "resource; regenerate it with: node scripts/gen-native-i18n.mjs .")
endif()
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/vgww_i18n.rc
    "24002 RCDATA \"${CMAKE_CURRENT_SOURCE_DIR}/src/ui/i18n_gen.bin\"\n")
target_sources(vgww PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/vgww_i18n.rc)

# Embed the application manifest (requireAdministrator: the process always
# starts elevated - the in-process driver DACL grant, install and uninstall
# need it, and the runas recovery paths then raise no UAC). The linker's
# auto-generated snippet would conflict on the <requestedExecutionLevel> tag,
# so suppress it and inject ours with mt.exe after the link.
if(MSVC)
    target_link_options(vgww PRIVATE /MANIFEST:NO)
    add_custom_command(TARGET vgww POST_BUILD
        COMMAND mt.exe -nologo -manifest
                ${CMAKE_CURRENT_SOURCE_DIR}/src/vgww.manifest
                -outputresource:$<TARGET_FILE:vgww>;#1
        COMMENT "Embedding elevated (requireAdministrator) application manifest")
endif()

# GUI-subsystem executable with an optional HTTP management backend (--web /
# --web-only). Batch19 R3-�? vgww now starts with the native window and no
# console window (the old CONSOLE subsystem flashed a console on every
# double-click and made tools/ui-shot.ps1 skip a ConsoleWindowClass window).
# main.cpp keeps both entry points: MSVC picks wWinMainCRTStartup for a
# WINDOWS-subsystem link automatically (verified: no explicit /ENTRY needed).
# The one-shot CLI flags attach to the parent console on demand (attach only,
# never AllocConsole), and pipes/redirection keep working.
if(MSVC)
    set_target_properties(vgww PROPERTIES WIN32_EXECUTABLE TRUE)
endif()

# Ship the ndisrd driver payload next to vgww.exe. The built-in installer
# (src/driver/installer.cpp) resolves ndisrd.sys / ndisrd_lwf.inf / ndisrd.cat
# from the executable directory, so a build that omits them makes
# --install-driver fail with "driver payload not found" on every machine.
# win10/11 is the supported target, so the win10 variants are used; win7/win8
# payloads under extract/.../win7|win8 are deliberately not copied.
set(VGWW_DRIVER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/winpkfilter")
add_custom_command(TARGET vgww POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${VGWW_DRIVER_DIR}/ndisrd.sys"
            "${VGWW_DRIVER_DIR}/ndisrd_lwf.inf"
            "${VGWW_DRIVER_DIR}/extract/PFiles64/Windows Packet Filter/drivers/win10/ndisrd.cat"
            "$<TARGET_FILE_DIR:vgww>"
    COMMENT "Copying ndisrd driver payload next to vgww.exe")

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
# Long-running soak/load harness (manual diagnostic: NOT registered with
# ctest). Build: cmake --build <dir> --config Release --target vgww_soak
add_executable(vgww_soak tools/soak.cpp)
target_link_libraries(vgww_soak PRIVATE vgww_core xtcp_static)

if(VGWW_BUILD_TESTS)
    enable_testing()
    add_executable(test_spsc_ring tests/test_spsc_ring.cpp)
    target_link_libraries(test_spsc_ring PRIVATE vgww_core)
    add_test(NAME spsc_ring COMMAND test_spsc_ring)

    add_executable(test_rate_limiter tests/test_rate_limiter.cpp)
    target_link_libraries(test_rate_limiter PRIVATE vgww_core)
    add_test(NAME rate_limiter COMMAND test_rate_limiter)

    add_executable(test_config tests/test_config.cpp)
    target_link_libraries(test_config PRIVATE vgww_core)
    add_test(NAME config COMMAND test_config)
    # S3-Task4-F1: run from the exe directory so the
    # "../../config.example.json" probe resolves to the repository sample
    # (<build>\Release -> <repo root>). The directory always exists at
    # test time (it holds the just-built exe); no MAKE_DIRECTORY needed.
    set_tests_properties(config PROPERTIES
        WORKING_DIRECTORY "$<TARGET_FILE_DIR:test_config>")

    add_executable(test_random tests/test_random.cpp)
    target_link_libraries(test_random PRIVATE vgww_core)
    add_test(NAME random COMMAND test_random)

    add_executable(test_neighbors tests/test_neighbors.cpp)
    target_link_libraries(test_neighbors PRIVATE vgww_core)
    add_test(NAME neighbors COMMAND test_neighbors)

    add_executable(test_memory tests/test_memory.cpp)
    target_link_libraries(test_memory PRIVATE vgww_core)
    add_test(NAME memory COMMAND test_memory)

    add_executable(test_udp_relay tests/test_udp_relay.cpp)
    target_link_libraries(test_udp_relay PRIVATE vgww_core)
    add_test(NAME udp_relay COMMAND test_udp_relay)

    add_executable(test_icmp tests/test_icmp.cpp)
    target_link_libraries(test_icmp PRIVATE vgww_core)
    add_test(NAME icmp COMMAND test_icmp)
    add_executable(test_eth tests/test_eth.cpp)
    target_link_libraries(test_eth PRIVATE vgww_core)
    add_test(NAME eth COMMAND test_eth)
    add_executable(test_ip_addr tests/test_ip_addr.cpp)
    target_link_libraries(test_ip_addr PRIVATE vgww_core)
    add_test(NAME ip_addr COMMAND test_ip_addr)
    add_executable(test_text tests/test_text.cpp)
    target_link_libraries(test_text PRIVATE vgww_core)
    add_test(NAME text COMMAND test_text)
    add_executable(test_checksum tests/test_checksum.cpp)
    target_link_libraries(test_checksum PRIVATE vgww_core)
    add_test(NAME checksum COMMAND test_checksum)
    add_executable(test_tcp_relay tests/test_tcp_relay.cpp)
    target_link_libraries(test_tcp_relay PRIVATE vgww_core xtcp_static)
    add_test(NAME tcp_relay COMMAND test_tcp_relay)
    add_executable(test_medium_fixes tests/test_medium_fixes.cpp)
    target_link_libraries(test_medium_fixes PRIVATE vgww_core xtcp_static)
    add_test(NAME medium_fixes COMMAND test_medium_fixes)

    add_executable(test_fuzz_parsers tests/test_fuzz_parsers.cpp)
    target_link_libraries(test_fuzz_parsers PRIVATE vgww_core)
    add_test(NAME fuzz_parsers COMMAND test_fuzz_parsers)

    add_executable(test_icmp_relay tests/test_icmp_relay.cpp)
    target_link_libraries(test_icmp_relay PRIVATE vgww_core)
    add_test(NAME icmp_relay COMMAND test_icmp_relay)

    add_executable(test_ndp tests/test_ndp.cpp)
    target_link_libraries(test_ndp PRIVATE vgww_core)
    add_test(NAME ndp COMMAND test_ndp)

    add_executable(test_classifier tests/test_classifier.cpp)
    target_link_libraries(test_classifier PRIVATE vgww_core)
    add_test(NAME classifier COMMAND test_classifier)

    add_executable(test_dhcp tests/test_dhcp.cpp)
    target_link_libraries(test_dhcp PRIVATE vgww_core)
    add_test(NAME dhcp COMMAND test_dhcp)

    add_executable(test_dhcp6 tests/test_dhcp6.cpp)
    target_link_libraries(test_dhcp6 PRIVATE vgww_core)
    add_test(NAME dhcp6 COMMAND test_dhcp6)

    add_executable(test_bridge tests/test_bridge.cpp)
    # xtcp_static: the Task 3 bridge tests drive Dataplane (dataplane.o
    # references the xtcp stack); no new target, link-only change.
    target_link_libraries(test_bridge PRIVATE vgww_core xtcp_static)
    add_test(NAME bridge COMMAND test_bridge)

    add_executable(test_arp_icmp tests/test_arp_icmp.cpp)
    target_link_libraries(test_arp_icmp PRIVATE vgww_core)
    add_test(NAME arp_icmp COMMAND test_arp_icmp)

    add_executable(test_web tests/test_web.cpp)
    target_link_libraries(test_web PRIVATE vgww_core xtcp_static)
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/web-test-cwd)
    add_test(NAME web COMMAND test_web WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/web-test-cwd)

    # Batch 16: installer tests live in their own target so they never share
    # a directory/payload with the web suite (the old in-test_web installer
    # block synthesized payloads next to the test binary, interfering with
    # the driver_payload ctest).
    add_executable(test_driver_installer tests/test_driver_installer.cpp)
    target_link_libraries(test_driver_installer PRIVATE vgww_core)
    add_test(NAME driver_installer COMMAND test_driver_installer)

    add_executable(test_dataplane tests/test_dataplane.cpp)
    target_link_libraries(test_dataplane PRIVATE vgww_core xtcp_static)
    add_test(NAME dataplane COMMAND test_dataplane)

    add_executable(test_dataplane_lifecycle tests/test_dataplane_lifecycle.cpp)
    target_link_libraries(test_dataplane_lifecycle PRIVATE vgww_core xtcp_static vgww_ui)
    add_test(NAME dataplane_lifecycle COMMAND test_dataplane_lifecycle)

    add_executable(test_portmap_manager tests/test_portmap_manager.cpp)
    target_link_libraries(test_portmap_manager PRIVATE vgww_core xtcp_static)
    add_test(NAME portmap_manager COMMAND test_portmap_manager)

    # Live-driver probe (manual diagnostic, NOT registered with ctest:
    # it touches the real ndisrd adapter and would disturb the host).
    add_executable(test_udp_proto tests/test_udp_proto.cpp)
    target_link_libraries(test_udp_proto PRIVATE vgww_core)
    add_test(NAME udp_proto COMMAND test_udp_proto)

    add_executable(test_ui_state tests/test_ui_state.cpp)
    target_link_libraries(test_ui_state PRIVATE vgww_ui xtcp_static)
    add_test(NAME ui_state COMMAND test_ui_state)

    add_executable(test_ndisrd_client tests/test_ndisrd_client.cpp)
    target_link_libraries(test_ndisrd_client PRIVATE vgww_core)
    add_test(NAME ndisrd_client COMMAND test_ndisrd_client)

    add_executable(test_ndisrd_live tests/test_ndisrd_live.cpp)
    target_link_libraries(test_ndisrd_live PRIVATE vgww_core)

    add_executable(test_main tests/test_main.cpp)
    target_link_libraries(test_main PRIVATE vgww_core)
    target_include_directories(test_main PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    add_test(NAME main COMMAND test_main)

    # batch23: the single-instance kernel-event gate lives in a header-only
    # module (src/ui/single_instance.h); this target exercises it headless
    # (no window). user32 is only needed by ActivateRunningInstance, which the
    # tests do not call, but linking it keeps the header self-contained.
    # batch247: page_util (MakeAdapterLabel / BuildAdapterChoices / Narrow /
    # ShortDeviceLabel / FirstIpv4) had zero direct coverage; only end-to-end
    # page tests touched it. Link vgww_ui like test_ui does.
    # batch248: ui_debug_serialize (SerializeElement / ElementPath / the three
    # finders) had zero coverage although three product call sites consume
    # ElementPath's indices as positions into SerializeElement's children[].
    # batch249: debug_state.h (Utf16ToUtf8 + the DebugWrite overload set) had
    # zero direct coverage although 18 product call sites depend on it for
    # every string the UI debug channel emits. Header-only: no vgww_ui link.
    # batch252: the tray icon geometry + colour seams (PackIconPixel,
    # FillAppIconPixels) had almost no direct coverage: 21 mutations killed 2.
    add_executable(test_tray tests/test_tray.cpp)
    target_link_libraries(test_tray PRIVATE vgww_ui xtcp_static)
    target_sources(test_tray PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/vgww_i18n.rc)
    add_test(NAME tray COMMAND test_tray)
    add_executable(test_debug_state tests/test_debug_state.cpp)
    target_include_directories(test_debug_state PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    add_test(NAME debug_state COMMAND test_debug_state)
    add_executable(test_ui_debug_serialize tests/test_ui_debug_serialize.cpp)
    target_link_libraries(test_ui_debug_serialize PRIVATE vgww_ui xtcp_static)
    add_test(NAME ui_debug_serialize COMMAND test_ui_debug_serialize)
    add_executable(test_page_util tests/test_page_util.cpp)
    target_link_libraries(test_page_util PRIVATE vgww_ui xtcp_static)
    target_sources(test_page_util PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/vgww_i18n.rc)
    add_test(NAME page_util COMMAND test_page_util)
    add_executable(test_single_instance tests/test_single_instance.cpp)
    target_link_libraries(test_single_instance PRIVATE user32)
    target_include_directories(test_single_instance PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    add_test(NAME single_instance COMMAND test_single_instance)

    add_executable(test_ui tests/test_ui.cpp)
    # M5: vgww_ui links xtcp_static privately; its lib pulls Dataplane -> xtcp
    # symbols, so the consuming test declares the dependency to link.
    target_link_libraries(test_ui PRIVATE vgww_ui xtcp_static)
    # Batch19 R4-P0: same M1 resource so I18n::SetLangCode can lazily decode
    # a language block in the test process.
    target_sources(test_ui PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/vgww_i18n.rc)
    add_test(NAME ui COMMAND test_ui)

    add_executable(test_sync tests/test_sync.cpp)
    target_link_libraries(test_sync PRIVATE vgww_ui xtcp_static)
    add_test(NAME sync COMMAND test_sync)

    # ---- web quality gates (S4.6-W0/W7): node scripts under scripts/ ----
    # Each gate takes the repo root as argv[1] and exits 0/1, so ctest
    # reports them like any other test. Node is only required when tests
    # are enabled.
    find_program(VGWW_NODE_EXECUTABLE NAMES node node.exe)
    if(NOT VGWW_NODE_EXECUTABLE)
        message(FATAL_ERROR
            "VGWW_BUILD_TESTS=ON requires node/node.exe on PATH for the web quality gates (scripts/check-*.mjs)")
    endif()
    add_test(NAME web_js_syntax COMMAND ${VGWW_NODE_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-js-syntax.mjs ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME web_i18n COMMAND ${VGWW_NODE_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-i18n.mjs ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME web_api_contract COMMAND ${VGWW_NODE_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-api-contract.mjs ${CMAKE_CURRENT_SOURCE_DIR})
    # Batch19 R4-P0: native (non-web) i18n resource gate.
    add_test(NAME native_i18n COMMAND ${VGWW_NODE_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-native-i18n.mjs ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME web_html_safety COMMAND ${VGWW_NODE_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-html-safety.mjs ${CMAKE_CURRENT_SOURCE_DIR})
    # batch147: the only gate that EXECUTES the inline console script (the
    # others are static). It drives the rate-limit editor through a minimal DOM
    # stub and asserts the JSON body the page posts, so a state-machine
    # regression is a red test instead of a rule silently deleted in production.
    add_test(NAME web_logic COMMAND ${VGWW_NODE_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-web-logic.mjs ${CMAKE_CURRENT_SOURCE_DIR})
    # batch153: every class name the page puts on an element must have a rule in
    # its own <style>. `.cl-out` (the console box) and `.spd` (the live-traffic
    # cue) both shipped as dead names: the markup promised a style nobody wrote,
    # so the console had no scroll box and the traffic highlight never showed.
    add_test(NAME web_css COMMAND ${VGWW_NODE_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-web-css.mjs ${CMAKE_CURRENT_SOURCE_DIR})
    # batch160: every visible form control needs an accessible name from an
    # explicit source, and no two may share one. The page shipped with fourteen
    # unnamed controls and three selects all named "Devices" (filter / sort key
    # / sort direction), which a screen reader cannot tell apart.
    add_test(NAME web_a11y COMMAND ${VGWW_NODE_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-web-a11y.mjs ${CMAKE_CURRENT_SOURCE_DIR})
    # batch226: every static tool that reads this tree (gates, greps, AST
    # scrapers) answers with whatever files are here. An editor backup sitting
    # in src/ui/pages/ made `OnIntent` look like it had 11 sites instead of 8,
    # and its OLDER LeasesPage::OnIntent read as a second dispatcher. It was
    # never compiled (this list is explicit) so no test could see it.
    add_test(NAME source_hygiene COMMAND ${VGWW_NODE_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-source-hygiene.mjs ${CMAKE_CURRENT_SOURCE_DIR})
    # batch207: the gate over the gates. Every check-*.mjs is a rule that can
    # silently stop policing, and six consecutive audits found exactly that by
    # hand (method ignored, empty CSS rule counted, injection APIs unknown,
    # dangling aria target accepted, empty translation passed, placeholder order
    # unchecked). This test runs each gate twice - once on clean input (must
    # pass) and once on input carrying the defect that gate exists to reject
    # (must fail FOR THAT REASON) - so weakening a gate now fails the build
    # instead of waiting for the next manual mutation.
    add_test(NAME gates_selftest COMMAND ${VGWW_NODE_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-gates-selftest.mjs ${CMAKE_CURRENT_SOURCE_DIR})

    # The built-in installer (src/driver/installer.cpp) resolves the ndisrd
    # payload from the vgww.exe directory; fail if the build did not place
    # ndisrd.sys / ndisrd_lwf.inf / ndisrd.cat next to the executable.
    add_test(NAME driver_payload
        COMMAND ${CMAKE_COMMAND}
            -DPAYLOAD_DIR=$<TARGET_FILE_DIR:vgww>
            -P ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-driver-payload.cmake)

    # batch210: a registered test can be deleted and nothing notices - ctest
    # then reports "34 tests, 100% passed", which is indistinguishable from a
    # healthy run. That is the same disease batch209 fixed one level down (a
    # JS gate printing a smaller case count and exiting 0), so it gets the
    # same treatment here: a FLOOR on the number of registered tests.
    #
    # CMake 3.20 exposes the directory's tests as a property, so this is a
    # configure-time check: dropping an add_test() line fails configuration
    # instead of quietly shrinking the suite. Raise the number when adding
    # tests; a deliberate removal lowers it in the same commit, which is what
    # makes the removal reviewable.
    get_property(vgww_registered_tests DIRECTORY PROPERTY TESTS)
    list(LENGTH vgww_registered_tests vgww_test_count)
    set(VGWW_MIN_TESTS 49)
    if(vgww_test_count LESS VGWW_MIN_TESTS)
        message(FATAL_ERROR
            "Only ${vgww_test_count} test(s) are registered, but at least ${VGWW_MIN_TESTS} are required. "
            "A test registration was removed (or lost during an edit). Restore it, or - if the "
            "removal is intentional - lower VGWW_MIN_TESTS in the same commit so it is reviewed.")
    endif()
endif()






