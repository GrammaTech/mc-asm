#include "mcasm.h"
#include "JSONStreamer.h"
#include "version.h"
#include <llvm/MC/MCAsmBackend.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCCodeEmitter.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCExpr.h>
#include <llvm/MC/MCFixupKindInfo.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCParser/MCTargetAsmParser.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSectionCOFF.h>
#include <llvm/MC/MCSectionELF.h>
#include <llvm/MC/MCSectionMachO.h>
#include <llvm/MC/MCStreamer.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/Support/Host.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <mutex>

using namespace llvm;

struct MCAssemblerImp {
  const Target* TheTarget = nullptr;
  Triple TheTriple;
  std::string LastJSON;
  bool PrettyPrint = false;
  MCX86Syntax Syntax = MC_X86_SYNTAX_ATT;
};

static void Init() {
  static std::once_flag Once;

  // The LLVM headers say that initialization call be called more than once,
  // but I have concerns about thread safety.
  std::call_once(Once, [] {
    InitializeAllAsmParsers();
    InitializeAllTargetInfos();
    InitializeAllTargetMCs();
  });
}

const char* MCDefaultTriple() {
  static std::string Result = sys::getDefaultTargetTriple();
  return Result.c_str();
}

const char* MCErrorToString(MCError Err) {
  switch (Err) {
  case MC_ERROR_SUCCESS:
    return "success";
  case MC_ERROR_FAILED_WITH_DIAGNOSTICS:
    return "failed with diagnostics";
  case MC_ERROR_UNSUPPORTED_TARGET:
    return "unsupported target triple";
  case MC_ERROR_FAILED:
    return "failed (unknown reason)";
  case MC_ERROR_INVALID_OPTION:
    return "invalid option";
  case MC_ERROR_INVALID_OPTION_VALUE:
    return "invalid option value";
  }
  return "<<INVALID ERROR>>";
}

void MCLibraryVersion(unsigned* Major, unsigned* Minor, unsigned* Patch) {
  if (Major)
    *Major = MCASM_MAJOR_VERSION;
  if (Minor)
    *Minor = MCASM_MINOR_VERSION;
  if (Patch)
    *Patch = MCASM_PATCH_VERSION;
}

void MCLLVMVersion(unsigned* Major, unsigned* Minor, unsigned* Patch) {
  if (Major)
    *Major = LLVM_VERSION_MAJOR;
  if (Minor)
    *Minor = LLVM_VERSION_MINOR;
  if (Patch)
    *Patch = LLVM_VERSION_PATCH;
}

MCError MCAssemblerCreate(const char* TargetTriple,
                          MCAssemblerRef* OutAssembler) {
  Init();

  Triple TheTriple(Triple::normalize(TargetTriple));
  std::string Error;
  const Target* TheTarget =
      TargetRegistry::lookupTarget(TheTriple.getTriple(), Error);
  if (!TheTarget)
    return MC_ERROR_UNSUPPORTED_TARGET;

  std::unique_ptr<MCAssemblerImp> Result = std::make_unique<MCAssemblerImp>();
  Result->TheTarget = TheTarget;
  Result->TheTriple = TheTriple;
  *OutAssembler = Result.release();
  return MC_ERROR_SUCCESS;
}

struct DiagContext {
  bool Errors = false;
  json::Array& Events;
};

static std::string ToJSON(SourceMgr::DiagKind Kind) {
  switch (Kind) {
  case SourceMgr::DK_Error:
    return "error";
  case SourceMgr::DK_Warning:
    return "warning";
  case SourceMgr::DK_Remark:
    return "remark";
  case SourceMgr::DK_Note:
    return "note";
  }
  llvm_unreachable("unknown diagnostic kind");
}

static json::Object ToJSON(const SMDiagnostic& Diag) {
  // We don't need to emit the file name because we'll only ever have the
  // single buffer from memory.
  return json::Object{
      {"kind", ToJSON(Diag.getKind())},
      {"message", std::string(Diag.getMessage())},
      {"line", Diag.getLineNo()},
      {"column", Diag.getColumnNo()},
  };
}

static void DiagCallback(const SMDiagnostic& Diag, void* Context) {
  DiagContext* DiagCtx = static_cast<DiagContext*>(Context);
  if (Diag.getKind() == SourceMgr::DK_Error)
    DiagCtx->Errors = true;
  DiagCtx->Events.push_back(json::Object{
      {"kind", "diagnostic"},
      {"diagnostic", ToJSON(Diag)},
  });
}

MCError MCAssemblerSetOption(MCAssemblerRef Assembler, MCOption Opt,
                             size_t Value) {
  switch (Opt) {
  case MC_OPTION_X86_SYNTAX:
    switch (Value) {
    case MC_X86_SYNTAX_ATT:
    case MC_X86_SYNTAX_INTEL:
      Assembler->Syntax = static_cast<MCX86Syntax>(Value);
      return MC_ERROR_SUCCESS;
    default:
      return MC_ERROR_INVALID_OPTION_VALUE;
    }
  case MC_OPTION_PRETTY_PRINT:
    switch (Value) {
    case 0:
      Assembler->PrettyPrint = false;
      return MC_ERROR_SUCCESS;
    case 1:
      Assembler->PrettyPrint = true;
      return MC_ERROR_SUCCESS;
    default:
      return MC_ERROR_INVALID_OPTION_VALUE;
    }
  }
  return MC_ERROR_INVALID_OPTION;
}

MCError MCAssemblerAssembleToJSON(MCAssemblerRef Assembler, const char* Input,
                                  char const** OutJSON) {
  Assembler->LastJSON.clear();

  MCTargetOptions MCOptions;

  std::unique_ptr<MCRegisterInfo> MRI(
      Assembler->TheTarget->createMCRegInfo(Assembler->TheTriple.getTriple()));
  std::unique_ptr<MCAsmInfo> MAI(Assembler->TheTarget->createMCAsmInfo(
      *MRI, Assembler->TheTriple.getTriple(), MCOptions));

  std::unique_ptr<MCInstrInfo> MCII(Assembler->TheTarget->createMCInstrInfo());
  std::unique_ptr<MCSubtargetInfo> STI(
      Assembler->TheTarget->createMCSubtargetInfo(
          Assembler->TheTriple.getTriple(), /*MCPU=*/"", /*FeaturesStr=*/""));
  std::unique_ptr<MCAsmBackend> MAB(
      Assembler->TheTarget->createMCAsmBackend(*STI, *MRI, MCOptions));

  json::Array Events;
  DiagContext DiagCtx{false, Events};

  SourceMgr SrcMgr;
  SrcMgr.AddNewSourceBuffer(MemoryBuffer::getMemBuffer(Input), SMLoc());
  SrcMgr.setDiagHandler(DiagCallback, &DiagCtx);

  MCObjectFileInfo MOFI;
  MCContext Ctx(MAI.get(), MRI.get(), &MOFI);
  MOFI.InitMCObjectFileInfo(Assembler->TheTriple, /*PIC=*/false, Ctx);

  std::unique_ptr<MCCodeEmitter> CE(
      Assembler->TheTarget->createMCCodeEmitter(*MCII, *MRI, Ctx));
  std::unique_ptr<MCStreamer> Str(createJSONStreamer(
      Assembler->TheTriple, Ctx, *CE, *MAB, *MCII, *MRI, Events));
  Str->setUseAssemblerInfoForParsing(true);

  std::unique_ptr<MCAsmParser> Parser(
      createMCAsmParser(SrcMgr, Ctx, *Str, *MAI));
  std::unique_ptr<MCTargetAsmParser> TAP(
      Assembler->TheTarget->createMCAsmParser(*STI, *Parser, *MCII, MCOptions));
  if (!TAP)
    return MC_ERROR_UNSUPPORTED_TARGET;

  // There doesn't really exist great symbolic constants for the dialects.
  if (Assembler->TheTriple.isX86()) {
    switch (Assembler->Syntax) {
    case MC_X86_SYNTAX_ATT:
      Parser->setAssemblerDialect(0);
      break;
    case MC_X86_SYNTAX_INTEL:
      Parser->setAssemblerDialect(1);
      break;
    }
  }

  Parser->setTargetParser(*TAP);
  int Res = Parser->Run(/*NoInitialTextSection=*/false);
  if (Res && !DiagCtx.Errors)
    return MC_ERROR_FAILED;

  raw_string_ostream(Assembler->LastJSON) << formatv(
      Assembler->PrettyPrint ? "{0:2}" : "{0}", json::Value(std::move(Events)));
  *OutJSON = Assembler->LastJSON.c_str();

  return DiagCtx.Errors ? MC_ERROR_FAILED_WITH_DIAGNOSTICS : MC_ERROR_SUCCESS;
}

void MCAssemblerDestroy(MCAssemblerRef Assembler) { delete Assembler; }
