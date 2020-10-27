find_package(LLVM 11 CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")

include(AddLLVM)
include(LLVMConfig)
include(HandleLLVMOptions)

# Library and headers
configure_file("${CMAKE_SOURCE_DIR}/include/mcasm/version.h.in"
               "${CMAKE_BINARY_DIR}/include/mcasm/version.h" @ONLY)

set(MCASM_HEADERS "${CMAKE_SOURCE_DIR}/include/mcasm/mcasm.h"
                  "${CMAKE_BINARY_DIR}/include/mcasm/version.h")

add_library(mcasm ${CMAKE_CURRENT_SOURCE_DIR}/MCASM.cpp
                  ${CMAKE_CURRENT_SOURCE_DIR}/JSONStreamer.cpp ${MCASM_HEADERS})

llvm_config(
  mcasm
  AllTargetsAsmParsers
  AllTargetsDescs
  AllTargetsInfos
  MC
  MCParser
  Support)

llvm_update_compile_flags(mcasm)

set_target_properties(mcasm PROPERTIES VERSION ${mcasm_VERSION}
                                       SOVERSION ${MCASM_MAJOR_VERSION})

set_target_properties(mcasm PROPERTIES CMAKE_CXX_VISIBILITY_PRESET hidden)

if(WIN32)
  set_target_properties(mcasm PROPERTIES PREFIX "lib")
endif()

target_compile_definitions(mcasm PRIVATE MC_USE_DLL_EXPORTS)

# https://stackoverflow.com/a/14863432
#
# Also, this is using target_link_libraries because the target_link_options does
# not exist in older versions of CMake.
if(UNIX)
  target_link_libraries(mcasm INTERFACE "-Wl,--exclude-libs,ALL")
endif()

target_include_directories(
  mcasm PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include/mcasm>)
target_include_directories(
  mcasm PUBLIC $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include/mcasm>)
target_include_directories(mcasm SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})

install_linux_debug_info(mcasm mcasm-debug-file)

install(
  TARGETS mcasm
  EXPORT mcasmTargets
  COMPONENT library
  INCLUDES
  DESTINATION include
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)
install(
  FILES ${MCASM_HEADERS}
  DESTINATION include
  COMPONENT headers)

# Driver
add_executable(mcasm-driver ${MCASM_HEADERS}
                            ${CMAKE_CURRENT_SOURCE_DIR}/driver.cpp)
set_target_properties(mcasm-driver PROPERTIES OUTPUT_NAME "mcasm")

llvm_config(mcasm-driver Support)

llvm_update_compile_flags(mcasm-driver)

target_link_libraries(mcasm-driver PRIVATE mcasm)
target_include_directories(mcasm-driver SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})

install_linux_debug_info(mcasm-driver mcasm-driver-debug-file)

install(
  TARGETS mcasm-driver
  DESTINATION bin
  COMPONENT driver)
