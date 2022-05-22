#include "state.h"
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

namespace py = pybind11;
using namespace py::literals;

namespace pybind11 {
namespace detail {
template <> struct type_caster<llvm::StringRef> {
public:
  PYBIND11_TYPE_CASTER(llvm::StringRef, const_name("str"));

  static handle cast(llvm::StringRef src, return_value_policy, handle) {
    handle s = PyUnicode_DecodeUTF8(src.data(), src.size(), nullptr);
    if (!s) {
      throw py::error_already_set();
    }
    return s;
  }
};

} // namespace detail
} // namespace pybind11
