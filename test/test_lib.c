#include <assert.h>
#include <mcasm.h>
#include <string.h>

int main() {
  MCAssemblerRef AS;
  MCError Err = MCAssemblerCreate("x86_64-linux-gnu", &AS);
  assert(!Err);
  assert(AS);

  Err = MCAssemblerSetOption(AS, MC_OPTION_PRETTY_PRINT, 1);
  assert(!Err);

  Err = MCAssemblerSetOption(AS, MC_OPTION_X86_SYNTAX, MC_X86_SYNTAX_ATT);
  assert(!Err);

  const char* JSONData;
  Err = MCAssemblerAssembleToJSON(AS, "ud2", &JSONData);
  assert(!Err);
  assert(JSONData);
  assert(strstr(JSONData, "0f0b"));

  MCAssemblerDestroy(AS);
  return 0;
}
