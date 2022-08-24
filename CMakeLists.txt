cmake_minimum_required(VERSION 3.15...3.22)

project(mcasm)

# ---------------------------------------------------------------------------
# CMake dependencies
# ---------------------------------------------------------------------------

if(SKBUILD)
  # Scikit-Build does not add your site-packages to the search path
  # automatically, so we need to add it _or_ the pybind11 specific directory
  # here.
  execute_process(
    COMMAND "${PYTHON_EXECUTABLE}" -c
            "import pybind11; print(pybind11.get_cmake_dir())"
    OUTPUT_VARIABLE _tmp_dir
    OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ECHO STDOUT)
  list(APPEND CMAKE_PREFIX_PATH "${_tmp_dir}")
endif()

# Now we can find pybind11
find_package(pybind11 CONFIG REQUIRED)

find_package(LLVM 14 CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")

include(AddLLVM)
include(LLVMConfig)
include(HandleLLVMOptions)

# ---------------------------------------------------------------------------
# Compile options
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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
  add_compile_options(-Wall -Wextra -Wpointer-arith -Werror)
  add_compile_options(-fPIC)
endif()

# ---------------------------------------------------------------------------
# Debug info
# ---------------------------------------------------------------------------
function(install_linux_debug_info TARGET COMPONENT_NAME)
  if(UNIX
     AND NOT CYGWIN
     AND NOT APPLE
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

# ---------------------------------------------------------------------------
# Extension target
# ---------------------------------------------------------------------------
pybind11_add_module(_core MODULE src/bind.cpp src/mc.cpp)

llvm_config(
  _core
  AllTargetsAsmParsers
  AllTargetsDescs
  AllTargetsInfos
  MC
  MCParser
  Support)

# We unfortunately need a version of LLVM built with RTTI. We need RTTI for our
# library due to pybind11 and because we inherit from an LLVM class
# (MCStreamer), we can end up with a reference to LLVM RTTI.
#
# It _might_ be possible to get around this by ensuring that StreamerAdaptor's
# vtable gets emitted in a file with -fno-rtti, but it's not that big a problem
# (yet?).
if(NOT LLVM_ENABLE_RTTI)
  message("LLVM must be built with RTTI (-DLLVM_ENABLE_RTTI=ON)" FATAL_ERROR)
endif()

# LLVM probably was not built with exception handling, but our code needs to be
# for pybind11. This is okay because we're careful not to propogate exceptions
# through LLVM frames.
set(LLVM_ENABLE_EH ON)

llvm_update_compile_flags(_core)

target_include_directories(_core SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})

install(TARGETS _core DESTINATION .)
install_linux_debug_info(_core _core-debug-file)
