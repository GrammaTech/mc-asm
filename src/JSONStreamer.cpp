#include <llvm/MC/MCAsmBackend.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCCodeEmitter.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCExpr.h>
#include <llvm/MC/MCFixupKindInfo.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCSectionCOFF.h>
#include <llvm/MC/MCSectionELF.h>
#include <llvm/MC/MCSectionMachO.h>
#include <llvm/MC/MCStreamer.h>
#include <llvm/Support/JSON.h>

#if LLVM_VERSION_MAJOR == 11
// These headers were copied from the LLVM release because they are not
// packaged as part of LLVM (due to being internal to each target). When
// updating LLVM versions, be sure to update the README as well.
#include "llvm-headers/AArch64MCExpr.h"
#include "llvm-headers/MipsMCExpr.h"
#else
#error "Unsupported LLVM version"
#endif

using namespace llvm;

class JSONStreamer : public MCStreamer {
public:
  JSONStreamer(Triple TargetTriple_, MCContext& Ctx_, MCCodeEmitter& CE_,
               MCAsmBackend& MAB_, MCInstrInfo& MCII_, MCRegisterInfo& MRI_,
               json::Array& Events_)
      : TargetTriple(TargetTriple_), Ctx(Ctx_), MCStreamer(Ctx_), CE(CE_),
        MAB(MAB_), MCII(MCII_), MRI(MRI_), Events(Events_) {}

  void emitLabel(MCSymbol* Symbol, SMLoc) override {
    Events.push_back(json::Object{
        {"kind", "label"},
        {"symbol", ToJSON(Symbol)},
    });
  }

  void emitSymbolDesc(MCSymbol* Symbol, unsigned DescValue) override {
    Events.push_back(json::Object{
        {"kind", "symbolDesc"},
        {"symbol", ToJSON(Symbol)},
        {"desc-value", DescValue},
    });
  }

  bool emitSymbolAttribute(MCSymbol* Symbol, MCSymbolAttr Attribute) override {
    Events.push_back(json::Object{
        {"kind", "symbolAttribute"},
        {"symbol", ToJSON(Symbol)},
        {"attribute", ToJSON(Attribute)},
    });
    return true;
  }

  void emitCommonSymbol(MCSymbol* Symbol, uint64_t Size,
                        unsigned ByteAlignment) override {
    Events.push_back(json::Object{
        {"kind", "commonSymbol"},
        {"symbol", ToJSON(Symbol)},
        {"size", static_cast<int64_t>(Size)},
        {"alignment", ByteAlignment},
    });
  }

  void emitZerofill(MCSection* Section, MCSymbol* Symbol = nullptr,
                    uint64_t Size = 0, unsigned ByteAlignment = 0,
                    SMLoc = SMLoc()) override {
    json::Object Event{
        {"kind", "zerofill"},
        {"section", ToJSON(Section)},
        {"size", static_cast<int64_t>(Size)},
        {"alignment", ByteAlignment},
    };
    if (Symbol)
      Event["symbol"] = ToJSON(Symbol);
    Events.push_back(std::move(Event));
  }

  void changeSection(MCSection* Section, const MCExpr* SubSection) override {
    json::Object Event{
        {"kind", "changeSection"},
        {"section", ToJSON(Section)},
    };
    if (SubSection)
      Event["subsection"] = ToJSON(SubSection);
    Events.push_back(std::move(Event));
  }

  void emitBytes(StringRef Data) override {
    Events.push_back(json::Object{
        {"kind", "bytes"},
        {"data", BytesToHexStr(Data)},
    });
  }

  void emitValueImpl(const MCExpr* Value, unsigned Size, SMLoc Loc) override {
    MCStreamer::emitValueImpl(Value, Size, Loc);
    Events.push_back(json::Object{
        {"kind", "emitValue"},
        {"value", ToJSON(Value)},
        {"size", Size},
    });
  }

  void emitInstruction(const MCInst& Inst,
                       const MCSubtargetInfo& STI) override {
    SmallVector<MCFixup, 4> Fixups;
    SmallString<256> Code;
    raw_svector_ostream VecOS(Code);
    CE.encodeInstruction(Inst, VecOS, Fixups, STI);

    json::Array FixupsJSON;
    for (MCFixup& Fixup : Fixups) {
      FixupsJSON.push_back(ToJSON(Fixup));
    }

    Events.push_back(json::Object{
        {"kind", "instruction"},
        {"inst", ToJSON(Inst)},
        {"data", BytesToHexStr(Code)},
        {"fixups", std::move(FixupsJSON)},
    });
  }

private:
  json::Object ToJSON(const MCSymbol* Sym) const {
    assert(Sym);

    return json::Object{
        {"name", Sym->getName()},
        // SymbolContents accessors
        {"isVariable", Sym->isVariable()},
        {"isUnset", Sym->isUnset()},
        {"isCommon", Sym->isCommon()},
        {"isTargetCommon", Sym->isTargetCommon()},

        {"isRegistered", Sym->isRegistered()},
        {"isUsedInReloc", Sym->isUsedInReloc()},
        {"isTemporary", Sym->isTemporary()},
        {"isUsed", Sym->isUsed()},
        {"isRedefinable", Sym->isRedefinable()},
        {"isDefined", Sym->isDefined()},
        {"isInSection", Sym->isInSection()},
        {"isAbsolute", Sym->isAbsolute()},
        {"isDefined", Sym->isDefined()},
        {"isExternal", Sym->isDefined()},
        {"isPrivateExtern", Sym->isDefined()},
    };
  }

  std::string ToJSON(MCBinaryExpr::Opcode Op) const {
    switch (Op) {
    case MCBinaryExpr::Add:
      return "Add";
    case MCBinaryExpr::And:
      return "And";
    case MCBinaryExpr::Div:
      return "Div";
    case MCBinaryExpr::EQ:
      return "EQ";
    case MCBinaryExpr::GT:
      return "GT";
    case MCBinaryExpr::GTE:
      return "GTE";
    case MCBinaryExpr::LAnd:
      return "LAdd";
    case MCBinaryExpr::LOr:
      return "LOr";
    case MCBinaryExpr::LT:
      return "LT";
    case MCBinaryExpr::LTE:
      return "LTE";
    case MCBinaryExpr::Mod:
      return "Mod";
    case MCBinaryExpr::Mul:
      return "Mul";
    case MCBinaryExpr::NE:
      return "NE";
    case MCBinaryExpr::Or:
      return "Or";
    case MCBinaryExpr::Shl:
      return "Shl";
    case MCBinaryExpr::AShr:
      return "AShr";
    case MCBinaryExpr::LShr:
      return "LShr";
    case MCBinaryExpr::Sub:
      return "Sub";
    case MCBinaryExpr::Xor:
      return "Xor";
    }

    llvm_unreachable("unknown binary expression opcode");
  }

  std::string ToJSON(MCUnaryExpr::Opcode Op) const {
    switch (Op) {
    case MCUnaryExpr::LNot:
      return "LNot";
    case MCUnaryExpr::Minus:
      return "Minus";
    case MCUnaryExpr::Not:
      return "Not";
    case MCUnaryExpr::Plus:
      return "Plus";
    }

    llvm_unreachable("unknown unary expression opcode");
  }

  json::Object ToJSON(const MCExpr* Expr) const {
    assert(Expr);

    if (auto CE = dyn_cast<MCConstantExpr>(Expr)) {
      return json::Object{
          {"kind", "constant"},
          {"value", CE->getValue()},
          {"useHexFormat", CE->useHexFormat()},
      };
    } else if (auto SRE = dyn_cast<MCSymbolRefExpr>(Expr)) {
      json::Object result{
          {"kind", "symbolRef"},
          {"hasSubsectionsViaSymbols", SRE->hasSubsectionsViaSymbols()},
          {"symbol", ToJSON(&SRE->getSymbol())},
      };
      if (SRE->getKind() != MCSymbolRefExpr::VK_None)
        result["variantKind"] =
            MCSymbolRefExpr::getVariantKindName(SRE->getKind());
      return result;
    } else if (auto UE = dyn_cast<MCUnaryExpr>(Expr)) {
      return json::Object{
          {"kind", "unaryExpr"},
          {"opcode", ToJSON(UE->getOpcode())},
          {"subExpr", ToJSON(UE->getSubExpr())},
      };
    } else if (auto BE = dyn_cast<MCBinaryExpr>(Expr)) {
      return json::Object{
          {"kind", "binaryExpr"},
          {"opcode", ToJSON(BE->getOpcode())},
          {"lhs", ToJSON(BE->getLHS())},
          {"rhs", ToJSON(BE->getRHS())},
      };
    } else if (auto TE = dyn_cast<MCTargetExpr>(Expr)) {
      if (TargetTriple.isAArch64()) {
        // This cast actually doesn't do any safety checking beyond checking
        // that it's a target expr.
        auto ATE = cast<AArch64MCExpr>(Expr);
        return json::Object{
            {"kind", "targetExpr"},
            {"target", "aarch64"},
            {"expr", ToJSON(ATE->getSubExpr())},
            {"elfName", ATE->getVariantKindName()},
        };
      } else if (TargetTriple.isMIPS()) {
        // This cast actually doesn't do any safety checking beyond checking
        // that it's a target expr.
        auto MTE = cast<MipsMCExpr>(Expr);
        return json::Object{
            {"kind", "targetExpr"},
            {"target", "mips"},
            {"expr", ToJSON(MTE->getSubExpr())},
            {"exprKind", ToJSON(MTE->getKind())},
        };
      } else {
        return json::Object{
            {"kind", "targetExpr"},
        };
      }
    }

    llvm_unreachable("unknown expression type");
  }

  json::Object ToJSON(const MCFixup& Fixup) const {
    const auto& KindInfo = MAB.getFixupKindInfo(Fixup.getKind());
    json::Array Flags;
    if (KindInfo.Flags & MCFixupKindInfo::FKF_IsPCRel)
      Flags.push_back("IsPCRel");
    if (KindInfo.Flags & MCFixupKindInfo::FKF_IsAlignedDownTo32Bits)
      Flags.push_back("IsAlignedDownTo32Bits");
    if (KindInfo.Flags & MCFixupKindInfo::FKF_IsTarget)
      Flags.push_back("IsTarget");
    if (KindInfo.Flags & MCFixupKindInfo::FKF_Constant)
      Flags.push_back("Constant");

    return json::Object{
        {"name", KindInfo.Name},
        {"offset", Fixup.getOffset()},
        {"value", ToJSON(Fixup.getValue())},
        {"targetOffset", KindInfo.TargetOffset},
        {"targetSize", KindInfo.TargetSize},
        {"flags", std::move(Flags)},
    };
  }

  json::Object ToJSON(const MCOperand* Op) const {
    assert(Op);

    if (!Op->isValid())
      return json::Object{
          {"kind", "invalid"},
      };
    if (Op->isReg()) {
      if (MCRegister(Op->getReg()).isValid()) {
        return json::Object{
            {"kind", "reg"},
            {"reg", MRI.getName(Op->getReg())},
        };
      } else {
        return json::Object{
            {"kind", "reg"},
            {"reg", nullptr},
        };
      }
    }
    if (Op->isImm())
      return json::Object{
          {"kind", "imm"},
          {"imm", Op->getImm()},
      };
    if (Op->isFPImm())
      return json::Object{
          {"kind", "fpImm"},
          {"imm", Op->getFPImm()},
      };
    if (Op->isExpr())
      return json::Object{
          {"kind", "expr"},
          {"expr", ToJSON(Op->getExpr())},
      };
    if (Op->isInst())
      return json::Object{
          {"kind", "inst"},
      };

    llvm_unreachable("unknown operand type");
  }

  json::Object ToJSON(const MCInstrDesc& ID) const {
    json::Array ImplicitUses;
    for (unsigned I = 0; I < ID.getNumImplicitUses(); I++) {
      const MCPhysReg& Reg = ID.getImplicitUses()[I];
      ImplicitUses.push_back(MRI.getName(Reg));
    }
    json::Array ImplicitDefs;
    for (unsigned I = 0; I < ID.getNumImplicitDefs(); I++) {
      const MCPhysReg& Reg = ID.getImplicitDefs()[I];
      ImplicitDefs.push_back(MRI.getName(Reg));
    }
    return json::Object{
        {"implicitUses", std::move(ImplicitUses)},
        {"implicitDefs", std::move(ImplicitDefs)},
        {"numDefs", ID.getNumDefs()},
        {"isVariadic", ID.isVariadic()},
        {"hasOptionalDef", ID.hasOptionalDef()},
        {"isPseudo", ID.isPseudo()},
        {"isReturn", ID.isReturn()},
        {"isAdd", ID.isAdd()},
        {"isTrap", ID.isTrap()},
        {"isMoveReg", ID.isMoveReg()},
        {"isCall", ID.isCall()},
        {"isBarrier", ID.isBarrier()},
        {"isTerminator", ID.isTerminator()},
        {"isBranch", ID.isBranch()},
        {"isIndirectBranch", ID.isIndirectBranch()},
        {"isConditionalBranch", ID.isConditionalBranch()},
        {"isUnconditionalBranch", ID.isUnconditionalBranch()},
        {"isPredicable", ID.isPredicable()},
        {"isCompare", ID.isCompare()},
        {"isMoveImmediate", ID.isMoveImmediate()},
        {"isBitcast", ID.isBitcast()},
        {"isSelect", ID.isSelect()},
        {"isNotDuplicable", ID.isNotDuplicable()},
        {"hasDelaySlot", ID.hasDelaySlot()},
        {"canFoldAsLoad", ID.canFoldAsLoad()},
        {"isRegSequenceLike", ID.isRegSequenceLike()},
        {"isExtractSubregLike", ID.isExtractSubregLike()},
        {"isInsertSubregLike", ID.isInsertSubregLike()},
        {"isConvergent", ID.isConvergent()},
        {"variadicOpsAreDefs", ID.variadicOpsAreDefs()},
        {"isAuthenticated", ID.isAuthenticated()},
        {"mayLoad", ID.mayLoad()},
        {"mayStore", ID.mayStore()},
        {"mayRaiseFPException", ID.mayRaiseFPException()},
        {"hasUnmodeledSideEffects", ID.hasUnmodeledSideEffects()},
    };
  }

  json::Object ToJSON(const MCInst& Inst) const {
    json::Array Operands;
    for (const auto& Op : Inst) {
      Operands.push_back(ToJSON(&Op));
    }
    return json::Object{
        {"opcode", MCII.getName(Inst.getOpcode())},
        {"operands", std::move(Operands)},
        {"flags", Inst.getFlags()},
        {"desc", ToJSON(MCII.get(Inst.getOpcode()))},
    };
  }

  json::Object ToJSON(const SectionKind& Kind) const {
    return json::Object{
        {"isMetadata", Kind.isMetadata()},
        {"isText", Kind.isText()},
        {"isExecuteOnly", Kind.isExecuteOnly()},
        {"isReadOnly", Kind.isReadOnly()},
        {"isMergeableCString", Kind.isMergeableCString()},
        {"isMergeableConst", Kind.isMergeableConst()},
        {"isWriteable", Kind.isWriteable()},
        {"isThreadLocal", Kind.isThreadLocal()},
        {"isThreadBSS", Kind.isThreadBSS()},
        {"isGlobalWriteableData", Kind.isGlobalWriteableData()},
        {"isBSS", Kind.isBSS()},
        {"isCommon", Kind.isCommon()},
        {"isData", Kind.isData()},
        {"isReadOnlyWithRel", Kind.isReadOnlyWithRel()},
    };
  }

  json::Object ToJSON(const MCSection* Sect) const {
    return json::Object{
        {"kind", ToJSON(Sect->getKind())},
        {"isVirtual", Sect->isVirtualSection()},
        {"alignment", Sect->getAlignment()},
        {"name", Sect->getName()},
    };
  }

  std::string ToJSON(MCSymbolAttr Attr) const {
    switch (Attr) {
    case MCSA_Invalid:
      return "<<INVALID>>";
    case MCSA_Cold:
      return "Cold";
    case MCSA_ELF_TypeFunction:
      return "ELF_TypeFunction";
    case MCSA_ELF_TypeIndFunction:
      return "ELF_TypeIndFunction";
    case MCSA_ELF_TypeObject:
      return "ELF_TypeObject";
    case MCSA_ELF_TypeTLS:
      return "ELF_TypeTLS";
    case MCSA_ELF_TypeCommon:
      return "ELF_TypeCommon";
    case MCSA_ELF_TypeNoType:
      return "ELF_TypeNoType";
    case MCSA_ELF_TypeGnuUniqueObject:
      return "ELF_TypeGnuUniqueObject";
    case MCSA_Global:
      return "Global";
    case MCSA_LGlobal:
      return "LGlobal";
    case MCSA_Hidden:
      return "Hidden";
    case MCSA_IndirectSymbol:
      return "IndirectSymbol";
    case MCSA_Internal:
      return "Internal";
    case MCSA_LazyReference:
      return "LazyReference";
    case MCSA_Local:
      return "Local";
    case MCSA_NoDeadStrip:
      return "NoDeadStrip";
    case MCSA_SymbolResolver:
      return "SymbolResolver";
    case MCSA_AltEntry:
      return "AltEntry";
    case MCSA_PrivateExtern:
      return "PrivateExtern";
    case MCSA_Protected:
      return "Protected";
    case MCSA_Reference:
      return "Reference";
    case MCSA_Weak:
      return "Weak";
    case MCSA_WeakDefinition:
      return "WeakDefinition";
    case MCSA_WeakReference:
      return "WeakReference";
    case MCSA_WeakDefAutoPrivate:
      return "WeakDefAutoPrivate";
    case MCSA_Extern:
      return "Extern";
    }

    llvm_unreachable("unknown symbol attr");
  }

  std::string ToJSON(MipsMCExpr::MipsExprKind Kind) const {
    switch (Kind) {
    case MipsMCExpr::MEK_None:
      return "None";
    case MipsMCExpr::MEK_CALL_HI16:
      return "CALL_HI16";
    case MipsMCExpr::MEK_CALL_LO16:
      return "CALL_LO16";
    case MipsMCExpr::MEK_DTPREL:
      return "DTPREL";
    case MipsMCExpr::MEK_DTPREL_HI:
      return "DTPREL_HI";
    case MipsMCExpr::MEK_DTPREL_LO:
      return "DTPREL_LO";
    case MipsMCExpr::MEK_GOT:
      return "GOT";
    case MipsMCExpr::MEK_GOTTPREL:
      return "GOTTPREL";
    case MipsMCExpr::MEK_GOT_CALL:
      return "GOT_CALL";
    case MipsMCExpr::MEK_GOT_DISP:
      return "GOT_DISP";
    case MipsMCExpr::MEK_GOT_HI16:
      return "GOT_HI16";
    case MipsMCExpr::MEK_GOT_LO16:
      return "GOT_LO16";
    case MipsMCExpr::MEK_GOT_OFST:
      return "GOT_OFST";
    case MipsMCExpr::MEK_GOT_PAGE:
      return "GOT_PAGE";
    case MipsMCExpr::MEK_GPREL:
      return "GPREL";
    case MipsMCExpr::MEK_HI:
      return "HI";
    case MipsMCExpr::MEK_HIGHER:
      return "HIGHER";
    case MipsMCExpr::MEK_HIGHEST:
      return "HIGHEST";
    case MipsMCExpr::MEK_LO:
      return "LO";
    case MipsMCExpr::MEK_NEG:
      return "NEG";
    case MipsMCExpr::MEK_PCREL_HI16:
      return "PCREL_HI16";
    case MipsMCExpr::MEK_PCREL_LO16:
      return "PCREL_LO16";
    case MipsMCExpr::MEK_TLSGD:
      return "TLSGD";
    case MipsMCExpr::MEK_TLSLDM:
      return "TLSLDM";
    case MipsMCExpr::MEK_TPREL_HI:
      return "TPREL_HI";
    case MipsMCExpr::MEK_TPREL_LO:
      return "TPREL_LO";
    case MipsMCExpr::MEK_Special:
      return "Special";
    }

    llvm_unreachable("unknown MipsExprKind");
  }

  SmallString<256> BytesToHexStr(StringRef Bytes) const {
    SmallString<256> Result;
    raw_svector_ostream OS(Result);
    for (unsigned char B : Bytes) {
      OS << format_hex_no_prefix(B, 2);
    }
    return Result;
  }

  Triple TargetTriple;
  MCContext& Ctx;
  MCCodeEmitter& CE;
  MCAsmBackend& MAB;
  MCInstrInfo& MCII;
  MCRegisterInfo& MRI;
  json::Array& Events;
};

std::unique_ptr<MCStreamer>
createJSONStreamer(Triple TargetTriple, MCContext& Ctx, MCCodeEmitter& CE,
                   MCAsmBackend& MAB, MCInstrInfo& MCII, MCRegisterInfo& MRI,
                   json::Array& Events) {
  return std::make_unique<JSONStreamer>(TargetTriple, Ctx, CE, MAB, MCII, MRI,
                                        Events);
}
