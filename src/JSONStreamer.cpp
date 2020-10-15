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

using namespace llvm;

static json::Object ToJSON(const MCSymbol* Sym) {
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

static std::string ToJSON(MCBinaryExpr::Opcode Op) {
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

static std::string ToJSON(MCUnaryExpr::Opcode Op) {
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

static json::Object ToJSON(const MCExpr* Expr) {
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
    (void)TE;
    return json::Object{
        {"kind", "targetExpr"},
    };
  }

  llvm_unreachable("unknown expression type");
}

static json::Object ToJSON(const MCAsmBackend& MAB, const MCFixup& Fixup) {
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

static json::Object ToJSON(MCRegisterInfo& MRI, const MCOperand* Op) {
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

json::Object ToJSON(MCRegisterInfo& MRI, const MCInstrDesc& ID) {
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

json::Object ToJSON(MCRegisterInfo& MRI, MCInstrInfo& MCII,
                    const MCInst& Inst) {
  json::Array Operands;
  for (const auto& Op : Inst) {
    Operands.push_back(ToJSON(MRI, &Op));
  }
  return json::Object{
      {"opcode", MCII.getName(Inst.getOpcode())},
      {"operands", std::move(Operands)},
      {"flags", Inst.getFlags()},
      {"desc", ToJSON(MRI, MCII.get(Inst.getOpcode()))},
  };
}

static json::Object ToJSON(const SectionKind& Kind) {
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

static json::Object ToJSON(const MCSection* Sect) {
  return json::Object{
      {"kind", ToJSON(Sect->getKind())},
      {"isVirtual", Sect->isVirtualSection()},
      {"alignment", Sect->getAlignment()},
      {"name", Sect->getName()},
  };
}

static std::string ToJSON(MCSymbolAttr Attr) {
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

static SmallString<256> BytesToHexStr(StringRef Bytes) {
  SmallString<256> Result;
  raw_svector_ostream OS(Result);
  for (unsigned char B : Bytes) {
    OS << format_hex_no_prefix(B, 2);
  }
  return Result;
}

class JSONStreamer : public MCStreamer {
public:
  JSONStreamer(MCContext& Ctx_, MCCodeEmitter& CE_, MCAsmBackend& MAB_,
               MCInstrInfo& MCII_, MCRegisterInfo& MRI_, json::Array& Events_)
      : MCStreamer(Ctx_), CE(CE_), MAB(MAB_), MCII(MCII_), MRI(MRI_),
        Events(Events_) {}

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
      FixupsJSON.push_back(ToJSON(MAB, Fixup));
    }

    Events.push_back(json::Object{
        {"kind", "instruction"},
        {"inst", ToJSON(MRI, MCII, Inst)},
        {"data", BytesToHexStr(Code)},
        {"fixups", std::move(FixupsJSON)},
    });
  }

private:
  MCCodeEmitter& CE;
  MCAsmBackend& MAB;
  MCInstrInfo& MCII;
  MCRegisterInfo& MRI;
  json::Array& Events;
};

std::unique_ptr<MCStreamer>
createJSONStreamer(MCContext& Ctx, MCCodeEmitter& CE, MCAsmBackend& MAB,
                   MCInstrInfo& MCII, MCRegisterInfo& MRI,
                   json::Array& Events) {
  return std::make_unique<JSONStreamer>(Ctx, CE, MAB, MCII, MRI, Events);
}
