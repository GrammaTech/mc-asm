#include "mcasm.h"
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FileUtilities.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/ToolOutputFile.h>

using namespace llvm;

static cl::opt<std::string>
    InputFilename(cl::Positional, cl::desc("<input file>"), cl::init("-"));

static cl::opt<std::string> OutputFilename("o", cl::desc("Output filename"),
                                           cl::value_desc("filename"),
                                           cl::init("-"));

static cl::opt<std::string> TargetTriple("target",
                                         cl::desc("Target to assemble for"),
                                         cl::init(MCDefaultTriple()));

static cl::opt<MCX86Syntax> X86Syntax(
    "x86-syntax",
    cl::values(clEnumValN(MC_X86_SYNTAX_ATT, "att", "AT&T syntax"),
               clEnumValN(MC_X86_SYNTAX_INTEL, "intel", "Intel syntax")),
    cl::init(MC_X86_SYNTAX_ATT));

void VersionPrinter(raw_ostream& OS) {
  unsigned Major, Minor, Patch;
  MCLibraryVersion(&Major, &Minor, &Patch);

  unsigned LLVMMajor, LLVMMinor, LLVMPatch;
  MCLLVMVersion(&LLVMMajor, &LLVMMinor, &LLVMPatch);

  OS << "mcasm " << Major << "." << Minor << "." << Patch;
  OS << " (LLVM " << LLVMMajor << "." << LLVMMinor << "." << LLVMPatch << ")\n";
}

int main(int argc, char** argv) {
  InitLLVM X(argc, argv);

  cl::SetVersionPrinter(VersionPrinter);
  cl::ParseCommandLineOptions(argc, argv, "llvm-based assembly parser\n");

  ErrorOr<std::unique_ptr<MemoryBuffer>> InputBuff =
      MemoryBuffer::getFileOrSTDIN(InputFilename);
  if (std::error_code EC = InputBuff.getError()) {
    errs() << "error opening " << InputFilename << ": " << EC.message() << '\n';
    return 1;
  }

  MCAssemblerRef AS = nullptr;
  MCError ASErr = MCAssemblerCreate(TargetTriple.getValue().c_str(), &AS);
  if (ASErr) {
    errs() << "error creating assembler: " << MCErrorToString(ASErr) << "\n";
    return 1;
  }

  ASErr = MCAssemblerSetOption(AS, MC_OPTION_PRETTY_PRINT, 1);
  assert(ASErr == MC_ERROR_SUCCESS);

  ASErr = MCAssemblerSetOption(AS, MC_OPTION_X86_SYNTAX, X86Syntax);
  assert(ASErr == MC_ERROR_SUCCESS);

  const char* JSONData;
  ASErr = MCAssemblerAssembleToJSON(AS, InputBuff.get()->getBufferStart(),
                                    &JSONData);
  if (ASErr != MC_ERROR_SUCCESS && ASErr != MC_ERROR_FAILED_WITH_DIAGNOSTICS) {
    errs() << "error assembling: " << MCErrorToString(ASErr) << "\n";
    MCAssemblerDestroy(AS);
    return 1;
  }

  std::error_code EC;
  raw_fd_ostream Out(OutputFilename, EC);
  if (EC) {
    errs() << "error: creating output file: " << EC.message() << '\n';
    return 1;
  }
  Out << JSONData << "\n";

  MCAssemblerDestroy(AS);
  return 0;
}
