enable_testing()

include_directories(${GTEST_INCLUDE_DIRS})

add_executable(mcasm_test mcasm.test.cpp main.test.cpp)

target_link_libraries(mcasm_test gtest gtest_main mcasm)

add_test(NAME mcasm_test COMMAND mcasm_test)

add_test(NAME testmcasm COMMAND $<TARGET_FILE:mcasm_test>)
