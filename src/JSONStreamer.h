#include <llvm/MC/MCAsmBackend.h>
#include <llvm/MC/MCCodeEmitter.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCStreamer.h>
#include <llvm/Support/JSON.h>

std::unique_ptr<llvm::MCStreamer>
createJSONStreamer(llvm::Triple TheTriple, llvm::MCContext& Ctx,
                   llvm::MCCodeEmitter& CE, llvm::MCAsmBackend& MAB,
                   llvm::MCInstrInfo& MCII, llvm::MCRegisterInfo& MRI,
                   llvm::json::Array& Events);
