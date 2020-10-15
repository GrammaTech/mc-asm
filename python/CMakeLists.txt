file(GLOB PY_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/mcams/*.py
     ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.py)

add_custom_target(python-sources ALL DEPENDS ${PY_SOURCES})
add_dependencies(python-sources mcasm)
add_custom_command(
  TARGET python-sources
  COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/mcasm"
          "${CMAKE_CURRENT_BINARY_DIR}/tests"
  COMMAND ${CMAKE_COMMAND} -E copy_directory "${CMAKE_CURRENT_SOURCE_DIR}/mcasm"
          "${CMAKE_CURRENT_BINARY_DIR}/mcasm"
  COMMAND ${CMAKE_COMMAND} -E copy_directory "${CMAKE_CURRENT_SOURCE_DIR}/tests"
          "${CMAKE_CURRENT_BINARY_DIR}/tests"
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:mcasm>
          "${CMAKE_CURRENT_BINARY_DIR}/mcasm/libmcasm.so")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/setup.py.in
               ${CMAKE_CURRENT_BINARY_DIR}/setup.py @ONLY)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/version.py.in
               ${CMAKE_CURRENT_SOURCE_DIR}/mcasm/version.py @ONLY)

if(MCASM_ENABLE_TESTS)
  add_test(
    NAME test-python
    COMMAND ${PYTHON} setup.py test
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/")
endif()

# Move the `setup.py install` command into a separate script. This extra layer
# of indirection allows us to detect the value of ENV{DESTDIR} at installation
# time, rather than configure time, so that the installation will go to the
# correct directory.

configure_file(install.cmake.in install.cmake @ONLY)
install(
  SCRIPT ${CMAKE_CURRENT_BINARY_DIR}/install.cmake
  COMPONENT python
  EXCLUDE_FROM_ALL)

# Convenience targets for installing python
add_custom_target(
  install-python
  DEPENDS python-sources
  COMMAND "${CMAKE_COMMAND}" -DCMAKE_INSTALL_COMPONENT=python -P
          "${CMAKE_BINARY_DIR}/cmake_install.cmake")

# The goal is to end up with a Python wheel that is specific to the platform of
# the shared library, but not a specific version or ABI of Python.
execute_process(
  COMMAND
    "${PYTHON}" -c
    "import distutils.util; print(distutils.util.get_platform().replace('-', '_').replace('.', '_'))"
  OUTPUT_VARIABLE DIST_PLATFORM)
add_custom_target(
  python-wheel
  DEPENDS python-sources
  COMMAND "${PYTHON}" setup.py bdist_wheel --plat-name ${DIST_PLATFORM})
