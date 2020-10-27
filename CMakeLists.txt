# Need 3.10 to support CXX_STANDARD=17
cmake_minimum_required(VERSION 3.10.0)

# Read version.txt and setup project
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/version.txt" VERSION_FILE)

string(REGEX MATCH "VERSION_MAJOR ([0-9]*)" _ ${VERSION_FILE})
set(MCASM_MAJOR_VERSION ${CMAKE_MATCH_1})

string(REGEX MATCH "VERSION_MINOR ([0-9]*)" _ ${VERSION_FILE})
set(MCASM_MINOR_VERSION ${CMAKE_MATCH_1})

string(REGEX MATCH "VERSION_PATCH ([0-9]*)" _ ${VERSION_FILE})
set(MCASM_PATCH_VERSION ${CMAKE_MATCH_1})

cmake_policy(SET CMP0048 NEW)
project(
  mcasm
  VERSION "${MCASM_MAJOR_VERSION}.${MCASM_MINOR_VERSION}.${MCASM_PATCH_VERSION}"
)

# ---------------------------------------------------------------------------
# Build options
# ---------------------------------------------------------------------------

# Wrapper for BUILD_SHARED_LIBS which defaults to 'ON'
option(MCASM_BUILD_SHARED_LIBS "Build shared libraries." ON)
if(MCASM_BUILD_SHARED_LIBS)
  set(BUILD_SHARED_LIBS ON)
else()
  set(BUILD_SHARED_LIBS OFF)
endif()

option(MCASM_ENABLE_TESTS "Enable build and running unit tests." ON)
if(MCASM_ENABLE_TESTS)
  enable_testing()
endif()

# ---------------------------------------------------------------------------
# Global settings
# ---------------------------------------------------------------------------

# set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# Use C++17
set(CMAKE_CXX_STANDARD 17)
# Error if it's not available
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
  set(CMAKE_DEBUG_POSTFIX
      "d"
      CACHE STRING "add a postfix, usually d on windows")
endif()
set(CMAKE_RELEASE_POSTFIX
    ""
    CACHE STRING "add a postfix, usually empty on windows")
set(CMAKE_RELWITHDEBINFO_POSTFIX
    ""
    CACHE STRING "add a postfix, usually empty on windows")
set(CMAKE_MINSIZEREL_POSTFIX
    ""
    CACHE STRING "add a postfix, usually empty on windows")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# ---------------------------------------------------------------------------
# Compile options
# ---------------------------------------------------------------------------
if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  add_compile_options(-D_MBCS)
  add_compile_options(-D_UNICODE)
  add_compile_options(-DUNICODE)
  add_compile_options(-D_WIN32)

  # Enabled a sensible warning level and treat all warnings as errors.
  add_compile_options(-W4)
  add_compile_options(-WX)
  add_compile_options(-D_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS)

  add_compile_options(-sdl) # Enable extra security checks
  add_compile_options(-wd4146)
  add_compile_options(-permissive-) # Disable permissive mode
  add_compile_options($<$<CONFIG:Release>:-GL>) # Enable whole program
                                                # optimization
  add_link_options($<$<CONFIG:Release>:-ltcg>) # Enable link-time code
                                               # generation
elseif((${CMAKE_CXX_COMPILER_ID} STREQUAL GNU) OR (${CMAKE_CXX_COMPILER_ID}
                                                   STREQUAL Clang))
  add_compile_options(-Wall -Wextra -Wpointer-arith -Wshadow -Werror)
  add_compile_options(-fPIC)
endif()

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

# ---------------------------------------------------------------------------
# Source files
# ---------------------------------------------------------------------------
function(install_linux_debug_info TARGET COMPONENT_NAME)
  if(UNIX
     AND NOT CYGWIN
     AND ("${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo"
          OR "${CMAKE_BUILD_TYPE}" STREQUAL "Debug"))
    string(
      RANDOM
      LENGTH 32
      ALPHABET "abcdef0123456789" BUILD_ID)
    string(SUBSTRING "${BUILD_ID}" 0 2 BUILD_ID_PREFIX)
    string(SUBSTRING "${BUILD_ID}" 2 32 BUILD_ID_SUFFIX)
    target_link_libraries(${TARGET} PRIVATE "-Wl,--build-id=0x${BUILD_ID}")
    add_custom_command(
      TARGET ${TARGET}
      POST_BUILD
      COMMAND objcopy --only-keep-debug $<TARGET_FILE:${TARGET}>
              ${CMAKE_BINARY_DIR}/bin/${BUILD_ID_SUFFIX}.debug
      COMMAND objcopy --strip-debug $<TARGET_FILE:${TARGET}>)
    install(
      FILES "${CMAKE_BINARY_DIR}/bin/${BUILD_ID_SUFFIX}.debug"
      COMPONENT "${COMPONENT_NAME}"
      DESTINATION "lib/debug/.build-id/${BUILD_ID_PREFIX}")
  endif()
endfunction()

# Add src subdirectory which contains targets
add_subdirectory(src)

find_program(PYTHON "python3")
if(PYTHON)
  add_subdirectory(python)
else()
  message(
    WARNING
      "Python interpreter not found; disabling building of Python API.
If this is in error, try giving -DPYTHON=... to CMake to specify what program to use."
  )
endif()

# ---------------------------------------------------------------------------
# Export config for use by other CMake projects
# ---------------------------------------------------------------------------
export(TARGETS mcasm FILE "${CMAKE_CURRENT_BINARY_DIR}/mcasmTargets.cmake")

# Build tree config
configure_file("${CMAKE_CURRENT_LIST_DIR}/mcasmConfig.cmake.in"
               "${CMAKE_CURRENT_BINARY_DIR}/mcasmConfig.cmake")

# Install tree config
configure_file("${CMAKE_CURRENT_LIST_DIR}/mcasmConfig.cmake.in"
               "${CMAKE_CURRENT_BINARY_DIR}/export/mcasmConfig.cmake")
install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/export/mcasmConfig.cmake
  DESTINATION lib/mcasm
  COMPONENT cmake_config)
install(
  EXPORT mcasmTargets
  DESTINATION lib/mcasm
  COMPONENT cmake_target)

export(PACKAGE mcasm)

# ---------------------------------------------------------------------------
# Debian package generation
# ---------------------------------------------------------------------------
set(CPACK_PROJECT_CONFIG_FILE ${CMAKE_CURRENT_SOURCE_DIR}/cpack-config.cmake)

set(CMAKE_PROJECT_HOMEPAGE_URL
    https://git.grammatech.com/rewriting/Templates/CMake)

set(CPACK_PACKAGE_VERSION_MAJOR ${MCASM_MAJOR_VERSION})
set(CPACK_PACKAGE_VERSION_MINOR ${MCASM_MINOR_VERSION})
set(CPACK_PACKAGE_VERSION_PATCH ${MCASM_PATCH_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Package description")
set(CPACK_PACKAGE_VENDOR "GrammaTech Inc.")
set(CPACK_PACKAGE_CONTACT someone@grammatech.com)
set(CPACK_PACKAGE_DESCRIPTION_FILE ${CMAKE_CURRENT_SOURCE_DIR}/README.md)
set(CPACK_PACKAGE_RESOURCE_FILE_LICENSE ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.txt)

set(CPACK_DEBIAN_PACKAGE_SECTION devel)

set(CPACK_MCASM_VERSION "${mcasm_VERSION}")

include(CPack)
