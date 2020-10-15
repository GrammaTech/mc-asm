#include "gtest/gtest.h"
#include "mcasm.hpp"

TEST(HelloTest, TestGrammaTech) {
  EXPECT_EQ("Hello, GrammaTech!", mcasm("GrammaTech"));
}
