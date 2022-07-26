#include "mc.h"
#include "casters.h"
using namespace mc;
using namespace llvm;
namespace py = pybind11;
using namespace py::literals;

template <typename WrapT, typename ValT>
static std::shared_ptr<WrapT> _wrap_simple(std::shared_ptr<ParserState> State,
                                           const ValT* Value) {
  if (Value)
    return std::make_shared<WrapT>(State, const_cast<ValT*>(Value));

  return nullptr;
}

std::shared_ptr<Symbol> mc::wrap(std::shared_ptr<ParserState> State,
                                 const MCSymbol* Sym) {
  return _wrap_simple<Symbol>(State, Sym);
}

std::shared_ptr<Expr> mc::wrap(std::shared_ptr<ParserState> State,
                               const MCExpr* Expr) {
  if (isa_and_nonnull<MCConstantExpr>(Expr)) {
    return std::make_shared<ConstantExpr>(State, const_cast<MCExpr*>(Expr));
  } else if (isa_and_nonnull<MCSymbolRefExpr>(Expr)) {
    return std::make_shared<SymbolRefExpr>(State, const_cast<MCExpr*>(Expr));
  } else if (isa_and_nonnull<MCBinaryExpr>(Expr)) {
    return std::make_shared<BinaryExpr>(State, const_cast<MCExpr*>(Expr));
  } else if (isa_and_nonnull<MCTargetExpr>(Expr)) {
    if (State->TheTriple.isAArch64()) {
      return std::make_shared<TargetExprAArch64>(State,
                                                 const_cast<MCExpr*>(Expr));
    } else {
      return std::make_shared<TargetExpr>(State, const_cast<MCExpr*>(Expr));
    }
  }
  return nullptr;
}

std::shared_ptr<SymbolRefExpr> mc::wrap(std::shared_ptr<ParserState> State,
                                        const MCSymbolRefExpr* SRE) {
  return _wrap_simple<SymbolRefExpr>(State, SRE);
}

std::shared_ptr<SourceLocation> mc::wrap(std::shared_ptr<ParserState> State,
                                         SMLoc Loc) {
  if (Loc.isValid())
    return std::make_shared<SourceLocation>(State, Loc);
  return nullptr;
}

std::shared_ptr<Section> mc::wrap(std::shared_ptr<ParserState> State,
                                  const MCSection* Value) {
  if (!Value)
    return nullptr;

  if (isa<MCSectionELF>(Value)) {
    return std::make_shared<SectionELF>(State, const_cast<MCSection*>(Value));
  } else if (isa<MCSectionCOFF>(Value)) {
    return std::make_shared<SectionCOFF>(State, const_cast<MCSection*>(Value));
  } else if (isa<MCSectionMachO>(Value)) {
    return std::make_shared<SectionMachO>(State, const_cast<MCSection*>(Value));
  }
  // If we don't know about the section class, just create an instance of the
  // base class.
  return std::make_shared<Section>(State, const_cast<MCSection*>(Value));
}

std::shared_ptr<Diagnostic> mc::wrap(std::shared_ptr<ParserState> State,
                                     const llvm::SMDiagnostic& Diag) {
  return std::make_shared<Diagnostic>(State, Diag);
}

std::shared_ptr<Instruction> mc::wrap(std::shared_ptr<ParserState> State,
                                      const llvm::MCInst& Inst) {
  return std::make_shared<Instruction>(State, Inst);
}

std::shared_ptr<InstructionDesc> mc::wrap(std::shared_ptr<ParserState> State,
                                          const llvm::MCInstrDesc& Desc) {
  return std::make_shared<InstructionDesc>(State, Desc);
}

std::shared_ptr<Fixup> mc::wrap(std::shared_ptr<ParserState> State,
                                const llvm::MCFixup& FU) {
  return std::make_shared<Fixup>(State, FU);
}

std::shared_ptr<FixupKindInfo> mc::wrap(std::shared_ptr<ParserState> State,
                                        llvm::MCFixupKindInfo const& FUI) {
  return std::make_shared<FixupKindInfo>(State, FUI);
}

std::shared_ptr<DwarfFrameInfo> mc::wrap(std::shared_ptr<ParserState> State,
                                         llvm::MCDwarfFrameInfo* DFI) {
  return std::make_shared<DwarfFrameInfo>(State, DFI);
}

std::shared_ptr<Register> mc::wrap(std::shared_ptr<ParserState> State,
                                   llvm::MCRegister Reg) {
  return std::make_shared<Register>(State, Reg);
}

py::object mc::wrap(std::shared_ptr<ParserState> State,
                    const llvm::MCOperand& Op) {
  if (Op.isReg()) {
    return py::cast(wrap(State, MCRegister::from(Op.getReg())));
  } else if (Op.isImm()) {
    return py::cast(Op.getImm());
  } else if (Op.isSFPImm()) {
    return py::cast(Op.getSFPImm());
  } else if (Op.isDFPImm()) {
    return py::cast(Op.getDFPImm());
  } else if (Op.isExpr()) {
    return py::cast(wrap(State, Op.getExpr()));
  } else if (Op.isInst() && Op.getInst()) {
    return py::cast(wrap(State, *Op.getInst()));
  }
  return py::none();
}

llvm::MCDwarfFrameInfo* mc::unwrap(std::shared_ptr<DwarfFrameInfo> Value) {
  return Value ? Value->get_raw_value() : nullptr;
}

llvm::MCInst& mc::unwrap(std::shared_ptr<Instruction> Value) {
  null_check(Value);
  return Value->get_raw_value();
}

llvm::SMLoc mc::unwrap(std::shared_ptr<SourceLocation> Value) {
  if (!Value)
    return SMLoc();
  return Value->get_raw_value();
}

llvm::MCSymbol* mc::unwrap(std::shared_ptr<Symbol> Value) {
  return Value ? Value->get_raw_value() : nullptr;
}

llvm::MCExpr* mc::unwrap(std::shared_ptr<Expr> Value) {
  return Value ? Value->get_raw_value() : nullptr;
}

llvm::MCSymbolRefExpr* mc::unwrap(std::shared_ptr<SymbolRefExpr> Value) {
  return Value ? Value->get_raw_value() : nullptr;
}

llvm::MCSection* mc::unwrap(std::shared_ptr<Section> Value) {
  return Value ? Value->get_raw_value() : nullptr;
}

llvm::MCRegister mc::unwrap(std::shared_ptr<Register> Value) {
  null_check(Value);
  return Value->get_raw_value();
}

template <class Type, class... Options>
using py_class_t = typename py::class_<Type, Options..., std::shared_ptr<Type>>;

void mc::register_module(py::module& mcasm) {
  py::module_ mc = mcasm.def_submodule("mc", "Wrappers for LLVM MC classes");

  py::enum_<MCSymbolAttr>(mc, "SymbolAttr")
      .value("Cold", MCSA_Cold)
      .value("ELF_TypeFunction", MCSA_ELF_TypeFunction)
      .value("ELF_TypeIndFunction", MCSA_ELF_TypeIndFunction)
      .value("ELF_TypeObject", MCSA_ELF_TypeObject)
      .value("ELF_TypeTLS", MCSA_ELF_TypeTLS)
      .value("ELF_TypeCommon", MCSA_ELF_TypeCommon)
      .value("ELF_TypeNoType", MCSA_ELF_TypeNoType)
      .value("ELF_TypeGnuUniqueObject", MCSA_ELF_TypeGnuUniqueObject)
      .value("Global", MCSA_Global)
      .value("LGlobal", MCSA_LGlobal)
      .value("Hidden", MCSA_Hidden)
      .value("IndirectSymbol", MCSA_IndirectSymbol)
      .value("Internal", MCSA_Internal)
      .value("LazyReference", MCSA_LazyReference)
      .value("Local", MCSA_Local)
      .value("NoDeadStrip", MCSA_NoDeadStrip)
      .value("SymbolResolver", MCSA_SymbolResolver)
      .value("AltEntry", MCSA_AltEntry)
      .value("PrivateExtern", MCSA_PrivateExtern)
      .value("Protected", MCSA_Protected)
      .value("Reference", MCSA_Reference)
      .value("Weak", MCSA_Weak)
      .value("WeakDefinition", MCSA_WeakDefinition)
      .value("WeakReference", MCSA_WeakReference)
      .value("WeakDefAutoPrivate", MCSA_WeakDefAutoPrivate);

  py::enum_<MCAssemblerFlag>(mc, "AssemblerFlag")
      .value("SyntaxUnified", MCAF_SyntaxUnified)
      .value("SubsectionsViaSymbols", MCAF_SubsectionsViaSymbols)
      .value("Code16", MCAF_Code16)
      .value("Code32", MCAF_Code32)
      .value("Code64", MCAF_Code64);

  py::enum_<MCDataRegionType>(mc, "DataRegionType")
      .value("DataRegion", MCDR_DataRegion)
      .value("DataRegionJT8", MCDR_DataRegionJT8)
      .value("DataRegionJT16", MCDR_DataRegionJT16)
      .value("DataRegionJT32", MCDR_DataRegionJT32)
      .value("DataRegionEnd", MCDR_DataRegionEnd);

  py::enum_<MCVersionMinType>(mc, "VersionMinType")
      .value("IOSVersionMin", MCVM_IOSVersionMin)
      .value("OSXVersionMin", MCVM_OSXVersionMin)
      .value("TvOSVersionMin", MCVM_TvOSVersionMin)
      .value("WatchOSVersionMin", MCVM_WatchOSVersionMin);

  py_class_t<Register>(mc, "Register")
      .def_property_readonly("id", &Register::get_id)
      .def_property_readonly("name", &Register::get_name)
      .def_property_readonly("is_physical_register",
                             &Register::get_is_physical_register)
      .def_property_readonly("is_stack_slot", &Register::get_is_stack_slot);

  py_class_t<Symbol>(mc, "Symbol")
      .def_property_readonly("name", &Symbol::get_name)
      .def_property_readonly("is_temporary", &Symbol::get_is_temporary);

  py_class_t<InstructionDesc>(mc, "InstructionDesc")
      .def_property_readonly("implicit_defs",
                             &InstructionDesc::get_implicit_defs)
      .def_property_readonly("implicit_uses",
                             &InstructionDesc::get_implicit_uses)
      .def_property_readonly("is_variadic", &InstructionDesc::get_is_variadic)
      .def_property_readonly("has_optional_def",
                             &InstructionDesc::get_has_optional_def)
      .def_property_readonly("is_pseudo", &InstructionDesc::get_is_pseudo)
      .def_property_readonly("is_return", &InstructionDesc::get_is_return)
      .def_property_readonly("is_add", &InstructionDesc::get_is_add)
      .def_property_readonly("is_trap", &InstructionDesc::get_is_trap)
      .def_property_readonly("is_move_reg", &InstructionDesc::get_is_move_reg)
      .def_property_readonly("is_call", &InstructionDesc::get_is_call)
      .def_property_readonly("is_barrier", &InstructionDesc::get_is_barrier)
      .def_property_readonly("is_terminator",
                             &InstructionDesc::get_is_terminator)
      .def_property_readonly("is_branch", &InstructionDesc::get_is_branch)
      .def_property_readonly("is_indirect_branch",
                             &InstructionDesc::get_is_indirect_branch)
      .def_property_readonly("is_conditional_branch",
                             &InstructionDesc::get_is_conditional_branch)
      .def_property_readonly("is_unconditional_branch",
                             &InstructionDesc::get_is_unconditional_branch)
      .def_property_readonly("is_predicable",
                             &InstructionDesc::get_is_predicable)
      .def_property_readonly("is_compare", &InstructionDesc::get_is_compare)
      .def_property_readonly("is_move_immediate",
                             &InstructionDesc::get_is_move_immediate)
      .def_property_readonly("is_bitcast", &InstructionDesc::get_is_bitcast)
      .def_property_readonly("is_select", &InstructionDesc::get_is_select)
      .def_property_readonly("is_not_duplicable",
                             &InstructionDesc::get_is_not_duplicable)
      .def_property_readonly("has_delay_slot",
                             &InstructionDesc::get_has_delay_slot)
      .def_property_readonly("can_fold_as_load",
                             &InstructionDesc::get_can_fold_as_load)
      .def_property_readonly("is_reg_sequence_like",
                             &InstructionDesc::get_is_reg_sequence_like)
      .def_property_readonly("is_extract_subreg_like",
                             &InstructionDesc::get_is_extract_subreg_like)
      .def_property_readonly("is_insert_subreg_like",
                             &InstructionDesc::get_is_insert_subreg_like)
      .def_property_readonly("is_convergent",
                             &InstructionDesc::get_is_convergent)
      .def_property_readonly("variadic_ops_are_defs",
                             &InstructionDesc::get_variadic_ops_are_defs)
      .def_property_readonly("is_authenticated",
                             &InstructionDesc::get_is_authenticated)
      .def_property_readonly("may_load", &InstructionDesc::get_may_load)
      .def_property_readonly("may_store", &InstructionDesc::get_may_store)
      .def_property_readonly("may_raise_fp_exception",
                             &InstructionDesc::get_may_raise_fp_exception)
      .def_property_readonly("has_unmodeled_side_effects",
                             &InstructionDesc::get_has_unmodeled_side_effects);

  py_class_t<Instruction>(mc, "Instruction")
      .def_property_readonly("opcode", &Instruction::get_opcode)
      .def_property_readonly("name", &Instruction::get_name)
      .def_property_readonly("desc", &Instruction::get_desc)
      .def_property_readonly("operands", &Instruction::get_operands);

  py_class_t<FixupKindInfo>(mc, "FixupKindInfo")
      .def_property_readonly("name", &FixupKindInfo::get_name)
      .def_property_readonly("bit_offset", &FixupKindInfo::get_bit_offset)
      .def_property_readonly("bit_size", &FixupKindInfo::get_bit_size)
      .def_property_readonly("is_pc_rel", &FixupKindInfo::get_is_pc_rel)
      .def_property_readonly("is_aligned_down_to_32_bits",
                             &FixupKindInfo::get_is_aligned_down_to_32_bits)
      .def_property_readonly("is_target_dependent",
                             &FixupKindInfo::get_is_target_dependent)
      .def_property_readonly("is_constant", &FixupKindInfo::get_is_constant);

  py_class_t<SourceLocation>(mc, "SourceLocation")
      .def("__iter__", &SourceLocation::iter)
      .def("__str__", &SourceLocation::str)
      .def_property_readonly("lineno", &SourceLocation::get_lineno)
      .def_property_readonly("offset", &SourceLocation::get_offset);

  py_class_t<DwarfFrameInfo>(mc, "DwarfFrameInfo");

  py_class_t<Section>(mc, "Section")
      .def_property_readonly("name", &Section::get_name);

  py_class_t<SectionELF, Section>(mc, "SectionELF")
      .def_property_readonly("type", &SectionELF::get_type)
      .def_property_readonly("flags", &SectionELF::get_flags);

  py_class_t<SectionCOFF, Section>(mc, "SectionCOFF")
      .def_property_readonly("characteristics",
                             &SectionCOFF::get_characteristics);

  py_class_t<SectionMachO, Section>(mc, "SectionMachO")
      .def_property_readonly("segment_name", &SectionMachO::get_segment_name);

  py_class_t<Expr>(mc, "Expr")
      .def_property_readonly("location", &Expr::get_location);

  auto symbol_ref_expr =
      py_class_t<SymbolRefExpr, Expr>(mc, "SymbolRefExpr")
          .def_property_readonly("symbol", &SymbolRefExpr::get_symbol);

  py::enum_<MCSymbolRefExpr::VariantKind>(symbol_ref_expr, "VariantKind")
      .value("None_", MCSymbolRefExpr::VK_None)
      .value("Invalid", MCSymbolRefExpr::VK_Invalid)
      .value("GOT", MCSymbolRefExpr::VK_GOT)
      .value("GOTOFF", MCSymbolRefExpr::VK_GOTOFF)
      .value("GOTREL", MCSymbolRefExpr::VK_GOTREL)
      .value("PCREL", MCSymbolRefExpr::VK_PCREL)
      .value("GOTPCREL", MCSymbolRefExpr::VK_GOTPCREL)
      .value("GOTTPOFF", MCSymbolRefExpr::VK_GOTTPOFF)
      .value("INDNTPOFF", MCSymbolRefExpr::VK_INDNTPOFF)
      .value("NTPOFF", MCSymbolRefExpr::VK_NTPOFF)
      .value("GOTNTPOFF", MCSymbolRefExpr::VK_GOTNTPOFF)
      .value("PLT", MCSymbolRefExpr::VK_PLT)
      .value("TLSGD", MCSymbolRefExpr::VK_TLSGD)
      .value("TLSLD", MCSymbolRefExpr::VK_TLSLD)
      .value("TLSLDM", MCSymbolRefExpr::VK_TLSLDM)
      .value("TPOFF", MCSymbolRefExpr::VK_TPOFF)
      .value("DTPOFF", MCSymbolRefExpr::VK_DTPOFF)
      .value("TLSCALL", MCSymbolRefExpr::VK_TLSCALL)
      .value("TLSDESC", MCSymbolRefExpr::VK_TLSDESC)
      .value("TLVP", MCSymbolRefExpr::VK_TLVP)
      .value("TLVPPAGE", MCSymbolRefExpr::VK_TLVPPAGE)
      .value("TLVPPAGEOFF", MCSymbolRefExpr::VK_TLVPPAGEOFF)
      .value("PAGE", MCSymbolRefExpr::VK_PAGE)
      .value("PAGEOFF", MCSymbolRefExpr::VK_PAGEOFF)
      .value("GOTPAGE", MCSymbolRefExpr::VK_GOTPAGE)
      .value("GOTPAGEOFF", MCSymbolRefExpr::VK_GOTPAGEOFF)
      .value("SECREL", MCSymbolRefExpr::VK_SECREL)
      .value("SIZE", MCSymbolRefExpr::VK_SIZE)
      .value("WEAKREF", MCSymbolRefExpr::VK_WEAKREF)
      .value("X86_ABS8", MCSymbolRefExpr::VK_X86_ABS8)
      .value("X86_PLTOFF", MCSymbolRefExpr::VK_X86_PLTOFF)
      .value("ARM_NONE", MCSymbolRefExpr::VK_ARM_NONE)
      .value("ARM_GOT_PREL", MCSymbolRefExpr::VK_ARM_GOT_PREL)
      .value("ARM_TARGET1", MCSymbolRefExpr::VK_ARM_TARGET1)
      .value("ARM_TARGET2", MCSymbolRefExpr::VK_ARM_TARGET2)
      .value("ARM_PREL31", MCSymbolRefExpr::VK_ARM_PREL31)
      .value("ARM_SBREL", MCSymbolRefExpr::VK_ARM_SBREL)
      .value("ARM_TLSLDO", MCSymbolRefExpr::VK_ARM_TLSLDO)
      .value("ARM_TLSDESCSEQ", MCSymbolRefExpr::VK_ARM_TLSDESCSEQ)
      .value("AVR_NONE", MCSymbolRefExpr::VK_AVR_NONE)
      .value("AVR_LO8", MCSymbolRefExpr::VK_AVR_LO8)
      .value("AVR_HI8", MCSymbolRefExpr::VK_AVR_HI8)
      .value("AVR_HLO8", MCSymbolRefExpr::VK_AVR_HLO8)
      .value("AVR_DIFF8", MCSymbolRefExpr::VK_AVR_DIFF8)
      .value("AVR_DIFF16", MCSymbolRefExpr::VK_AVR_DIFF16)
      .value("AVR_DIFF32", MCSymbolRefExpr::VK_AVR_DIFF32)
      .value("AVR_PM", MCSymbolRefExpr::VK_AVR_PM)
      .value("PPC_LO", MCSymbolRefExpr::VK_PPC_LO)
      .value("PPC_HI", MCSymbolRefExpr::VK_PPC_HI)
      .value("PPC_HA", MCSymbolRefExpr::VK_PPC_HA)
      .value("PPC_HIGH", MCSymbolRefExpr::VK_PPC_HIGH)
      .value("PPC_HIGHA", MCSymbolRefExpr::VK_PPC_HIGHA)
      .value("PPC_HIGHER", MCSymbolRefExpr::VK_PPC_HIGHER)
      .value("PPC_HIGHERA", MCSymbolRefExpr::VK_PPC_HIGHERA)
      .value("PPC_HIGHEST", MCSymbolRefExpr::VK_PPC_HIGHEST)
      .value("PPC_HIGHESTA", MCSymbolRefExpr::VK_PPC_HIGHESTA)
      .value("PPC_GOT_LO", MCSymbolRefExpr::VK_PPC_GOT_LO)
      .value("PPC_GOT_HI", MCSymbolRefExpr::VK_PPC_GOT_HI)
      .value("PPC_GOT_HA", MCSymbolRefExpr::VK_PPC_GOT_HA)
      .value("PPC_TOCBASE", MCSymbolRefExpr::VK_PPC_TOCBASE)
      .value("PPC_TOC", MCSymbolRefExpr::VK_PPC_TOC)
      .value("PPC_TOC_LO", MCSymbolRefExpr::VK_PPC_TOC_LO)
      .value("PPC_TOC_HI", MCSymbolRefExpr::VK_PPC_TOC_HI)
      .value("PPC_TOC_HA", MCSymbolRefExpr::VK_PPC_TOC_HA)
      .value("PPC_U", MCSymbolRefExpr::VK_PPC_U)
      .value("PPC_L", MCSymbolRefExpr::VK_PPC_L)
      .value("PPC_DTPMOD", MCSymbolRefExpr::VK_PPC_DTPMOD)
      .value("PPC_TPREL_LO", MCSymbolRefExpr::VK_PPC_TPREL_LO)
      .value("PPC_TPREL_HI", MCSymbolRefExpr::VK_PPC_TPREL_HI)
      .value("PPC_TPREL_HA", MCSymbolRefExpr::VK_PPC_TPREL_HA)
      .value("PPC_TPREL_HIGH", MCSymbolRefExpr::VK_PPC_TPREL_HIGH)
      .value("PPC_TPREL_HIGHA", MCSymbolRefExpr::VK_PPC_TPREL_HIGHA)
      .value("PPC_TPREL_HIGHER", MCSymbolRefExpr::VK_PPC_TPREL_HIGHER)
      .value("PPC_TPREL_HIGHERA", MCSymbolRefExpr::VK_PPC_TPREL_HIGHERA)
      .value("PPC_TPREL_HIGHEST", MCSymbolRefExpr::VK_PPC_TPREL_HIGHEST)
      .value("PPC_TPREL_HIGHESTA", MCSymbolRefExpr::VK_PPC_TPREL_HIGHESTA)
      .value("PPC_DTPREL_LO", MCSymbolRefExpr::VK_PPC_DTPREL_LO)
      .value("PPC_DTPREL_HI", MCSymbolRefExpr::VK_PPC_DTPREL_HI)
      .value("PPC_DTPREL_HA", MCSymbolRefExpr::VK_PPC_DTPREL_HA)
      .value("PPC_DTPREL_HIGH", MCSymbolRefExpr::VK_PPC_DTPREL_HIGH)
      .value("PPC_DTPREL_HIGHA", MCSymbolRefExpr::VK_PPC_DTPREL_HIGHA)
      .value("PPC_DTPREL_HIGHER", MCSymbolRefExpr::VK_PPC_DTPREL_HIGHER)
      .value("PPC_DTPREL_HIGHERA", MCSymbolRefExpr::VK_PPC_DTPREL_HIGHERA)
      .value("PPC_DTPREL_HIGHEST", MCSymbolRefExpr::VK_PPC_DTPREL_HIGHEST)
      .value("PPC_DTPREL_HIGHESTA", MCSymbolRefExpr::VK_PPC_DTPREL_HIGHESTA)
      .value("PPC_GOT_TPREL", MCSymbolRefExpr::VK_PPC_GOT_TPREL)
      .value("PPC_GOT_TPREL_LO", MCSymbolRefExpr::VK_PPC_GOT_TPREL_LO)
      .value("PPC_GOT_TPREL_HI", MCSymbolRefExpr::VK_PPC_GOT_TPREL_HI)
      .value("PPC_GOT_TPREL_HA", MCSymbolRefExpr::VK_PPC_GOT_TPREL_HA)
      .value("PPC_GOT_DTPREL", MCSymbolRefExpr::VK_PPC_GOT_DTPREL)
      .value("PPC_GOT_DTPREL_LO", MCSymbolRefExpr::VK_PPC_GOT_DTPREL_LO)
      .value("PPC_GOT_DTPREL_HI", MCSymbolRefExpr::VK_PPC_GOT_DTPREL_HI)
      .value("PPC_GOT_DTPREL_HA", MCSymbolRefExpr::VK_PPC_GOT_DTPREL_HA)
      .value("PPC_TLS", MCSymbolRefExpr::VK_PPC_TLS)
      .value("PPC_GOT_TLSGD", MCSymbolRefExpr::VK_PPC_GOT_TLSGD)
      .value("PPC_GOT_TLSGD_LO", MCSymbolRefExpr::VK_PPC_GOT_TLSGD_LO)
      .value("PPC_GOT_TLSGD_HI", MCSymbolRefExpr::VK_PPC_GOT_TLSGD_HI)
      .value("PPC_GOT_TLSGD_HA", MCSymbolRefExpr::VK_PPC_GOT_TLSGD_HA)
      .value("PPC_TLSGD", MCSymbolRefExpr::VK_PPC_TLSGD)
      .value("PPC_AIX_TLSGD", MCSymbolRefExpr::VK_PPC_AIX_TLSGD)
      .value("PPC_AIX_TLSGDM", MCSymbolRefExpr::VK_PPC_AIX_TLSGDM)
      .value("PPC_GOT_TLSLD", MCSymbolRefExpr::VK_PPC_GOT_TLSLD)
      .value("PPC_GOT_TLSLD_LO", MCSymbolRefExpr::VK_PPC_GOT_TLSLD_LO)
      .value("PPC_GOT_TLSLD_HI", MCSymbolRefExpr::VK_PPC_GOT_TLSLD_HI)
      .value("PPC_GOT_TLSLD_HA", MCSymbolRefExpr::VK_PPC_GOT_TLSLD_HA)
      .value("PPC_GOT_PCREL", MCSymbolRefExpr::VK_PPC_GOT_PCREL)
      .value("PPC_GOT_TLSGD_PCREL", MCSymbolRefExpr::VK_PPC_GOT_TLSGD_PCREL)
      .value("PPC_GOT_TLSLD_PCREL", MCSymbolRefExpr::VK_PPC_GOT_TLSLD_PCREL)
      .value("PPC_GOT_TPREL_PCREL", MCSymbolRefExpr::VK_PPC_GOT_TPREL_PCREL)
      .value("PPC_TLS_PCREL", MCSymbolRefExpr::VK_PPC_TLS_PCREL)
      .value("PPC_TLSLD", MCSymbolRefExpr::VK_PPC_TLSLD)
      .value("PPC_LOCAL", MCSymbolRefExpr::VK_PPC_LOCAL)
      .value("PPC_NOTOC", MCSymbolRefExpr::VK_PPC_NOTOC)
      .value("PPC_PCREL_OPT", MCSymbolRefExpr::VK_PPC_PCREL_OPT)
      .value("COFF_IMGREL32", MCSymbolRefExpr::VK_COFF_IMGREL32)
      .value("Hexagon_LO16", MCSymbolRefExpr::VK_Hexagon_LO16)
      .value("Hexagon_HI16", MCSymbolRefExpr::VK_Hexagon_HI16)
      .value("Hexagon_GPREL", MCSymbolRefExpr::VK_Hexagon_GPREL)
      .value("Hexagon_GD_GOT", MCSymbolRefExpr::VK_Hexagon_GD_GOT)
      .value("Hexagon_LD_GOT", MCSymbolRefExpr::VK_Hexagon_LD_GOT)
      .value("Hexagon_GD_PLT", MCSymbolRefExpr::VK_Hexagon_GD_PLT)
      .value("Hexagon_LD_PLT", MCSymbolRefExpr::VK_Hexagon_LD_PLT)
      .value("Hexagon_IE", MCSymbolRefExpr::VK_Hexagon_IE)
      .value("Hexagon_IE_GOT", MCSymbolRefExpr::VK_Hexagon_IE_GOT)
      .value("WASM_TYPEINDEX", MCSymbolRefExpr::VK_WASM_TYPEINDEX)
      .value("WASM_TLSREL", MCSymbolRefExpr::VK_WASM_TLSREL)
      .value("WASM_MBREL", MCSymbolRefExpr::VK_WASM_MBREL)
      .value("WASM_TBREL", MCSymbolRefExpr::VK_WASM_TBREL)
      .value("AMDGPU_GOTPCREL32_LO", MCSymbolRefExpr::VK_AMDGPU_GOTPCREL32_LO)
      .value("AMDGPU_GOTPCREL32_HI", MCSymbolRefExpr::VK_AMDGPU_GOTPCREL32_HI)
      .value("AMDGPU_REL32_LO", MCSymbolRefExpr::VK_AMDGPU_REL32_LO)
      .value("AMDGPU_REL32_HI", MCSymbolRefExpr::VK_AMDGPU_REL32_HI)
      .value("AMDGPU_REL64", MCSymbolRefExpr::VK_AMDGPU_REL64)
      .value("AMDGPU_ABS32_LO", MCSymbolRefExpr::VK_AMDGPU_ABS32_LO)
      .value("AMDGPU_ABS32_HI", MCSymbolRefExpr::VK_AMDGPU_ABS32_HI)
      .value("VE_HI32", MCSymbolRefExpr::VK_VE_HI32)
      .value("VE_LO32", MCSymbolRefExpr::VK_VE_LO32)
      .value("VE_PC_HI32", MCSymbolRefExpr::VK_VE_PC_HI32)
      .value("VE_PC_LO32", MCSymbolRefExpr::VK_VE_PC_LO32)
      .value("VE_GOT_HI32", MCSymbolRefExpr::VK_VE_GOT_HI32)
      .value("VE_GOT_LO32", MCSymbolRefExpr::VK_VE_GOT_LO32)
      .value("VE_GOTOFF_HI32", MCSymbolRefExpr::VK_VE_GOTOFF_HI32)
      .value("VE_GOTOFF_LO32", MCSymbolRefExpr::VK_VE_GOTOFF_LO32)
      .value("VE_PLT_HI32", MCSymbolRefExpr::VK_VE_PLT_HI32)
      .value("VE_PLT_LO32", MCSymbolRefExpr::VK_VE_PLT_LO32)
      .value("VE_TLS_GD_HI32", MCSymbolRefExpr::VK_VE_TLS_GD_HI32)
      .value("VE_TLS_GD_LO32", MCSymbolRefExpr::VK_VE_TLS_GD_LO32)
      .value("VE_TPOFF_HI32", MCSymbolRefExpr::VK_VE_TPOFF_HI32)
      .value("VE_TPOFF_LO32", MCSymbolRefExpr::VK_VE_TPOFF_LO32)
      .value("TPREL", MCSymbolRefExpr::VK_TPREL)
      .value("DTPREL", MCSymbolRefExpr::VK_DTPREL);

  symbol_ref_expr.def_property_readonly("variant_kind",
                                        &SymbolRefExpr::get_variant_kind);

  py_class_t<ConstantExpr, Expr>(mc, "ConstantExpr")
      .def_property_readonly("value", &ConstantExpr::get_value)
      .def_property_readonly("size_in_bytes", &ConstantExpr::get_size_in_bytes);

  py_class_t<TargetExpr, Expr>(mc, "TargetExpr");

  py_class_t<TargetExprAArch64, TargetExpr>(mc, "TargetExprAArch64")
      .def_property_readonly("sub_expr", &TargetExprAArch64::get_sub_expr)
      .def_property_readonly("variant_kind_name",
                             &TargetExprAArch64::get_variant_kind_name);

  py_class_t<TargetExprMips, TargetExpr>(mc, "TargetExprMips");

  auto binary_expr = py_class_t<BinaryExpr, Expr>(mc, "BinaryExpr")
                         .def_property_readonly("lhs", &BinaryExpr::get_lhs)
                         .def_property_readonly("rhs", &BinaryExpr::get_rhs);

  py::enum_<MCBinaryExpr::Opcode>(binary_expr, "Opcode")
      .value("Add", MCBinaryExpr::Add)
      .value("And", MCBinaryExpr::And)
      .value("Div", MCBinaryExpr::Div)
      .value("EQ", MCBinaryExpr::EQ)
      .value("GT", MCBinaryExpr::GT)
      .value("GTE", MCBinaryExpr::GTE)
      .value("LAnd", MCBinaryExpr::LAnd)
      .value("LOr", MCBinaryExpr::LOr)
      .value("LT", MCBinaryExpr::LT)
      .value("LTE", MCBinaryExpr::LTE)
      .value("Mod", MCBinaryExpr::Mod)
      .value("Mul", MCBinaryExpr::Mul)
      .value("NE", MCBinaryExpr::NE)
      .value("Or", MCBinaryExpr::Or)
      .value("OrNot", MCBinaryExpr::OrNot)
      .value("Shl", MCBinaryExpr::Shl)
      .value("AShr", MCBinaryExpr::AShr)
      .value("LShr", MCBinaryExpr::LShr)
      .value("Sub", MCBinaryExpr::Sub)
      .value("Xor", MCBinaryExpr::Xor);

  binary_expr.def_property_readonly("opcode", &BinaryExpr::get_opcode);

  py_class_t<Fixup>(mc, "Fixup")
      .def_property_readonly("kind_info", &Fixup::get_kind_info)
      .def_property_readonly("value", &Fixup::get_value)
      .def_property_readonly("offset", &Fixup::get_offset);

  auto diagnostic =
      py_class_t<Diagnostic>(mc, "Diagnostic")
          .def_property_readonly("lineno", &Diagnostic::get_lineno)
          .def_property_readonly("offset", &Diagnostic::get_offset)
          .def_property_readonly("message", &Diagnostic::get_message)
          .def_property_readonly("text", &Diagnostic::get_text);

  py::enum_<SourceMgr::DiagKind>(diagnostic, "Kind")
      .value("Error", SourceMgr::DK_Error)
      .value("Warning", SourceMgr::DK_Warning)
      .value("Remark", SourceMgr::DK_Remark)
      .value("Note", SourceMgr::DK_Note);

  diagnostic.def_property_readonly("kind", &Diagnostic::get_kind);
}
