cmake_minimum_required(VERSION 3.20)
project(policy-engine
        VERSION 1.0.0
        DESCRIPTION "Real-time SIM policy / authorization decision service"
        LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(POLICY_BUILD_TESTS     "Build the unit / property / golden test suite" ON)
option(POLICY_BUILD_BENCH     "Build the open-loop load generator"            ON)
option(POLICY_BUILD_TOOLS     "Build the data-generation tools"               ON)
option(POLICY_NATIVE_ARCH     "Compile with -march=native / -mcpu=native"      ON)
option(POLICY_LTO             "Enable link-time optimization for Release"      ON)
option(POLICY_ENABLE_IO_URING "Build the io_uring ingest backend (Linux)"      ON)
option(POLICY_ASAN            "Build with AddressSanitizer + UBSan"           OFF)
option(POLICY_TSAN            "Build with ThreadSanitizer"                    OFF)
option(POLICY_WERROR          "Treat warnings as errors"                      OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# ---------------------------------------------------------------------------
# Platform / feature detection
# ---------------------------------------------------------------------------
include(CheckCXXSourceCompiles)
include(CheckIncludeFileCXX)

set(POLICY_HAVE_MMSG 0)
set(POLICY_HAVE_AFFINITY 0)
set(POLICY_HAVE_IO_URING 0)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  check_cxx_source_compiles("
    #include <sys/socket.h>
    int main() { struct mmsghdr m{}; (void)m; recvmmsg(0, &m, 1, 0, nullptr); return 0; }
  " POLICY_CHECK_MMSG)
  if(POLICY_CHECK_MMSG)
    set(POLICY_HAVE_MMSG 1)
  endif()

  check_cxx_source_compiles("
    #include <sched.h>
    int main() { cpu_set_t s; CPU_ZERO(&s); CPU_SET(0, &s); return sched_setaffinity(0, sizeof(s), &s); }
  " POLICY_CHECK_AFFINITY)
  if(POLICY_CHECK_AFFINITY)
    set(POLICY_HAVE_AFFINITY 1)
  endif()

  if(POLICY_ENABLE_IO_URING)
    find_path(LIBURING_INCLUDE_DIR liburing.h)
    find_library(LIBURING_LIBRARY NAMES uring liburing)
    if(LIBURING_INCLUDE_DIR AND LIBURING_LIBRARY)
      set(POLICY_HAVE_IO_URING 1)
      message(STATUS "io_uring backend: enabled (${LIBURING_LIBRARY})")
    else()
      message(STATUS "io_uring backend: disabled (liburing not found)")
    endif()
  endif()
else()
  message(STATUS "Non-Linux host (${CMAKE_SYSTEM_NAME}): "
                 "batched syscalls, CPU pinning and io_uring fall back to portable paths")
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/build_config.hpp.in
               ${CMAKE_CURRENT_BINARY_DIR}/generated/policy/build_config.hpp @ONLY)

# ---------------------------------------------------------------------------
# Common compile settings
# ---------------------------------------------------------------------------
add_library(policy_flags INTERFACE)
target_compile_options(policy_flags INTERFACE
  -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
  -Wnon-virtual-dtor -Wold-style-cast -Wcast-align -Wunused -Woverloaded-virtual
  -Wdouble-promotion -Wformat=2 -Wno-gnu-zero-variadic-macro-arguments)

if(POLICY_WERROR)
  target_compile_options(policy_flags INTERFACE -Werror)
endif()

target_compile_options(policy_flags INTERFACE
  $<$<CONFIG:Release>:-O3;-fno-omit-frame-pointer>
  $<$<CONFIG:RelWithDebInfo>:-O2;-g;-fno-omit-frame-pointer>)

if(POLICY_NATIVE_ARCH AND NOT POLICY_ASAN AND NOT POLICY_TSAN)
  include(CheckCXXCompilerFlag)
  check_cxx_compiler_flag("-march=native" POLICY_HAS_MARCH_NATIVE)
  if(POLICY_HAS_MARCH_NATIVE)
    target_compile_options(policy_flags INTERFACE -march=native)
  else()
    check_cxx_compiler_flag("-mcpu=native" POLICY_HAS_MCPU_NATIVE)
    if(POLICY_HAS_MCPU_NATIVE)
      target_compile_options(policy_flags INTERFACE -mcpu=native)
    endif()
  endif()
endif()

if(POLICY_ASAN)
  target_compile_options(policy_flags INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1)
  target_link_options(policy_flags INTERFACE -fsanitize=address,undefined)
endif()
if(POLICY_TSAN)
  target_compile_options(policy_flags INTERFACE -fsanitize=thread -fno-omit-frame-pointer -g -O1)
  target_link_options(policy_flags INTERFACE -fsanitize=thread)
endif()

if(POLICY_LTO AND NOT POLICY_ASAN AND NOT POLICY_TSAN)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT POLICY_IPO_OK OUTPUT POLICY_IPO_MSG)
  if(POLICY_IPO_OK)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
  else()
    message(STATUS "LTO unavailable: ${POLICY_IPO_MSG}")
  endif()
endif()

find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# Core library — portable, no OS dependencies on the decision path
# ---------------------------------------------------------------------------
add_library(policy_core STATIC
  src/yaml.cpp
  src/rules.cpp
  src/subscriber_store.cpp
  src/engine.cpp
  src/config.cpp
  src/logging.cpp
  src/metrics.cpp
  src/golden.cpp)
target_include_directories(policy_core PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_link_libraries(policy_core PUBLIC policy_flags Threads::Threads)

# ---------------------------------------------------------------------------
# Networking / server library
# ---------------------------------------------------------------------------
add_library(policy_net STATIC
  src/net.cpp
  src/affinity.cpp
  src/server_udp.cpp
  src/server_iouring.cpp
  src/admin_http.cpp
  src/control_plane.cpp)
target_link_libraries(policy_net PUBLIC policy_core)
if(POLICY_HAVE_IO_URING)
  # SYSTEM, so liburing's own C-style casts and macros do not trip this
  # project's -Wold-style-cast/-Wconversion under -Werror. A third-party
  # header's style is not something this build should have an opinion about.
  target_include_directories(policy_net SYSTEM PUBLIC ${LIBURING_INCLUDE_DIR})
  target_link_libraries(policy_net PUBLIC ${LIBURING_LIBRARY})
  # Belt and braces: warnings from a macro expansion are sometimes attributed
  # to the expansion site rather than to the system header that defined it.
  set_source_files_properties(src/server_iouring.cpp PROPERTIES
    COMPILE_OPTIONS "-Wno-old-style-cast")
endif()

# ---------------------------------------------------------------------------
# Executables
# ---------------------------------------------------------------------------
add_executable(policyd src/main.cpp)
target_link_libraries(policyd PRIVATE policy_net)

if(POLICY_BUILD_BENCH)
  add_executable(policy-loadgen bench/loadgen.cpp)
  target_link_libraries(policy-loadgen PRIVATE policy_net)
endif()

if(POLICY_BUILD_TOOLS)
  add_executable(policy-gen-subscribers tools/gen_subscribers.cpp)
  target_link_libraries(policy-gen-subscribers PRIVATE policy_core)
  add_executable(policy-gen-golden tools/gen_golden.cpp)
  target_link_libraries(policy-gen-golden PRIVATE policy_core)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(POLICY_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

message(STATUS "policy-engine ${PROJECT_VERSION} | ${CMAKE_BUILD_TYPE} | ${CMAKE_CXX_COMPILER_ID} "
               "| mmsg=${POLICY_HAVE_MMSG} affinity=${POLICY_HAVE_AFFINITY} io_uring=${POLICY_HAVE_IO_URING}")
