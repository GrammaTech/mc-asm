#ifndef BASE_H
#define BASE_H

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
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <memory>

class StreamerBase;

class FriendlyStreamer : public llvm::MCStreamer {
  friend StreamerBase;
  using llvm::MCStreamer::MCStreamer;
};

class ParserState {
public:
  llvm::Triple TheTriple;
  llvm::MCTargetOptions MCOptions;
  std::unique_ptr<llvm::MCRegisterInfo> MRI;
  std::unique_ptr<llvm::MCAsmInfo> MAI;
  std::unique_ptr<llvm::MCInstrInfo> MCII;
  std::unique_ptr<llvm::MCSubtargetInfo> STI;
  std::unique_ptr<llvm::MCAsmBackend> MAB;
  llvm::SourceMgr SM;
  std::unique_ptr<llvm::MCContext> Ctx;
  std::unique_ptr<llvm::MCObjectFileInfo> MOFI;
  std::unique_ptr<llvm::MCCodeEmitter> CE;
  std::unique_ptr<FriendlyStreamer> Str;
  std::unique_ptr<llvm::MCAsmParser> Parser;
  std::unique_ptr<llvm::MCTargetAsmParser> TAP;
};

template <typename T> class ValueWithState {
public:
  ValueWithState(std::shared_ptr<ParserState> State, T Value)
      : State(State), Value(Value) {}

  T& get_raw_value() { return Value; }

protected:
  std::shared_ptr<ParserState> State;
  T Value;
};

#endif
