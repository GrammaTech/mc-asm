#ifndef EXPR_H
#define EXPR_H

#include "../src/llvm-headers/AArch64MCExpr.h"
#include "state.h"
#include <llvm/MC/MCExpr.h>
#include <pybind11/pybind11.h>
namespace py = pybind11;

namespace mc {

class Expr;
class SymbolRefExpr;
class Symbol;
class SourceLocation;
class Diagnostic;
class Instruction;
class Fixup;
class Section;
class InstructionDesc;
class DwarfFrameInfo;
class FixupKindInfo;
class Register;

template <typename T> void null_check(std::shared_ptr<T> value) {
  if (!value) {
    throw py::type_error("expected a valid value but got None");
  }
}

// wrap declarations

std::shared_ptr<Symbol> wrap(std::shared_ptr<ParserState> State,
                             const llvm::MCSymbol* Sym);

std::shared_ptr<Expr> wrap(std::shared_ptr<ParserState> State,
                           const llvm::MCExpr* Expr);

std::shared_ptr<SymbolRefExpr> wrap(std::shared_ptr<ParserState> State,
                                    const llvm::MCSymbolRefExpr* SRE);

std::shared_ptr<SourceLocation> wrap(std::shared_ptr<ParserState> State,
                                     llvm::SMLoc Loc);

std::shared_ptr<Section> wrap(std::shared_ptr<ParserState> State,
                              const llvm::MCSection* Value);

std::shared_ptr<Diagnostic> wrap(std::shared_ptr<ParserState> State,
                                 const llvm::SMDiagnostic& Diagnostic);

std::shared_ptr<Instruction> wrap(std::shared_ptr<ParserState> State,
                                  const llvm::MCInst& Inst);

std::shared_ptr<InstructionDesc> wrap(std::shared_ptr<ParserState> State,
                                      const llvm::MCInstrDesc& Desc);

std::shared_ptr<Fixup> wrap(std::shared_ptr<ParserState> State,
                            const llvm::MCFixup& FU);

std::shared_ptr<FixupKindInfo> wrap(std::shared_ptr<ParserState> State,
                                    const llvm::MCFixupKindInfo& FUI);

std::shared_ptr<DwarfFrameInfo> wrap(std::shared_ptr<ParserState> State,
                                     llvm::MCDwarfFrameInfo* DFI);

std::shared_ptr<Register> wrap(std::shared_ptr<ParserState> State,
                               llvm::MCRegister Reg);

py::object wrap(std::shared_ptr<ParserState> State, const llvm::MCOperand& Op);

// unwrap declarations

llvm::MCDwarfFrameInfo* unwrap(std::shared_ptr<DwarfFrameInfo> Value);

llvm::MCInst& unwrap(std::shared_ptr<Instruction> Value);

llvm::SMLoc unwrap(std::shared_ptr<SourceLocation> Value);

llvm::MCSymbol* unwrap(std::shared_ptr<Symbol> Value);

llvm::MCExpr* unwrap(std::shared_ptr<Expr> Value);

llvm::MCSymbolRefExpr* unwrap(std::shared_ptr<SymbolRefExpr> Value);

llvm::MCSection* unwrap(std::shared_ptr<Section> Value);

llvm::MCRegister unwrap(std::shared_ptr<Register> Value);

// mc class wrappers

class DwarfFrameInfo : public ValueWithState<llvm::MCDwarfFrameInfo*> {
public:
  using ValueWithState::ValueWithState;
};

class Register : public ValueWithState<llvm::MCRegister> {
public:
  using ValueWithState::ValueWithState;

  auto get_id() const { return Value.id(); }
  auto get_is_stack_slot() const {
    return llvm::MCRegister::isStackSlot(Value.id());
  }
  auto get_is_physical_register() const {
    return llvm::MCRegister::isPhysicalRegister(Value.id());
  }
  std::string get_name() const {
    if (llvm::MCRegister::isPhysicalRegister(Value.id())) {
      return State->MRI->getName(Value);
    }
    return "";
  }
};

class SourceLocation : public ValueWithState<llvm::SMLoc> {
public:
  using ValueWithState::ValueWithState;

  auto get_lineno() const {
    auto [Line, Col] = State->SM.getLineAndColumn(Value);
    return Line;
  }

  auto get_offset() const {
    auto [Line, Col] = State->SM.getLineAndColumn(Value);
    return Col;
  }

  auto iter() const {
    auto [Line, Col] = State->SM.getLineAndColumn(Value);
    return py::iter(py::make_tuple(Line, Col));
  }

  auto str() const {
    auto [Line, Col] = State->SM.getLineAndColumn(Value);
    return std::to_string(Line) + ":" + std::to_string(Col);
  }
};

class Symbol : public ValueWithState<llvm::MCSymbol*> {
public:
  using ValueWithState::ValueWithState;

  auto get_name() const { return Value->getName(); }
  auto get_is_temporary() const { return Value->isTemporary(); }
};

class InstructionDesc : public ValueWithState<llvm::MCInstrDesc> {
public:
  using ValueWithState::ValueWithState;

  auto get_implicit_uses() const {
    std::vector<std::shared_ptr<Register>> Results;
    for (unsigned i = 0; i < Value.getNumImplicitUses(); i++) {
      llvm::MCPhysReg Reg = Value.getImplicitUses()[i];
      Results.push_back(wrap(State, llvm::MCRegister::from(Reg)));
    }
    return Results;
  }

  auto get_implicit_defs() const {
    std::vector<std::shared_ptr<Register>> Results;
    for (unsigned i = 0; i < Value.getNumImplicitDefs(); i++) {
      llvm::MCPhysReg Reg = Value.getImplicitDefs()[i];
      Results.push_back(wrap(State, llvm::MCRegister::from(Reg)));
    }
    return Results;
  }

  auto get_is_variadic() const { return Value.isVariadic(); }
  auto get_has_optional_def() const { return Value.hasOptionalDef(); }
  auto get_is_pseudo() const { return Value.isPseudo(); }
  auto get_is_return() const { return Value.isReturn(); }
  auto get_is_add() const { return Value.isAdd(); }
  auto get_is_trap() const { return Value.isTrap(); }
  auto get_is_move_reg() const { return Value.isMoveReg(); }
  auto get_is_call() const { return Value.isCall(); }
  auto get_is_barrier() const { return Value.isBarrier(); }
  auto get_is_terminator() const { return Value.isTerminator(); }
  auto get_is_branch() const { return Value.isBranch(); }
  auto get_is_indirect_branch() const { return Value.isIndirectBranch(); }
  auto get_is_conditional_branch() const { return Value.isConditionalBranch(); }
  auto get_is_unconditional_branch() const {
    return Value.isUnconditionalBranch();
  }
  auto get_is_predicable() const { return Value.isPredicable(); }
  auto get_is_compare() const { return Value.isCompare(); }
  auto get_is_move_immediate() const { return Value.isMoveImmediate(); }
  auto get_is_bitcast() const { return Value.isBitcast(); }
  auto get_is_select() const { return Value.isSelect(); }
  auto get_is_not_duplicable() const { return Value.isNotDuplicable(); }
  auto get_has_delay_slot() const { return Value.hasDelaySlot(); }
  auto get_can_fold_as_load() const { return Value.canFoldAsLoad(); }
  auto get_is_reg_sequence_like() const { return Value.isRegSequenceLike(); }
  auto get_is_extract_subreg_like() const {
    return Value.isExtractSubregLike();
  }
  auto get_is_insert_subreg_like() const { return Value.isInsertSubregLike(); }
  auto get_is_convergent() const { return Value.isConvergent(); }
  auto get_variadic_ops_are_defs() const { return Value.variadicOpsAreDefs(); }
  auto get_is_authenticated() const { return Value.isAuthenticated(); }
  auto get_may_load() const { return Value.mayLoad(); }
  auto get_may_store() const { return Value.mayStore(); }
  auto get_may_raise_fp_exception() const {
    return Value.mayRaiseFPException();
  }
  auto get_has_unmodeled_side_effects() const {
    return Value.hasUnmodeledSideEffects();
  }
};

class Instruction : public ValueWithState<llvm::MCInst> {
public:
  using ValueWithState::ValueWithState;

  auto get_opcode() const { return Value.getOpcode(); }
  auto get_name() const { return State->MCII->getName(Value.getOpcode()); }
  auto get_desc() const {
    return wrap(State, State->MCII->get(Value.getOpcode()));
  }
  auto get_operands() const {
    std::vector<py::object> Results;
    for (unsigned i = 0; i < Value.getNumOperands(); i++) {
      Results.push_back(wrap(State, Value.getOperand(i)));
    }
    return Results;
  }
};

class FixupKindInfo : public ValueWithState<llvm::MCFixupKindInfo> {
public:
  using ValueWithState::ValueWithState;

  auto get_name() const { return Value.Name; }
  auto get_bit_offset() const { return Value.TargetOffset; }
  auto get_bit_size() const { return Value.TargetSize; }
  auto get_is_pc_rel() const {
    return Value.Flags & llvm::MCFixupKindInfo::FKF_IsPCRel;
  }
  auto get_is_aligned_down_to_32_bits() const {
    return Value.Flags & llvm::MCFixupKindInfo::FKF_IsAlignedDownTo32Bits;
  }
  auto get_is_target_dependent() const {
    return Value.Flags & llvm::MCFixupKindInfo::FKF_IsTarget;
  }
  auto get_is_constant() const {
    return Value.Flags & llvm::MCFixupKindInfo::FKF_Constant;
  }
};

class Fixup : public ValueWithState<llvm::MCFixup> {
public:
  using ValueWithState::ValueWithState;

  auto get_offset() const { return Value.getOffset(); }
  auto get_kind_info() const {
    const auto& KindInfo = State->MAB->getFixupKindInfo(Value.getKind());
    return wrap(State, KindInfo);
  }
  auto get_value() const { return wrap(State, Value.getValue()); }
};

class Diagnostic : public ValueWithState<llvm::SMDiagnostic> {
public:
  using ValueWithState::ValueWithState;

  auto get_lineno() const { return Value.getLineNo(); }
  auto get_offset() const { return Value.getColumnNo(); }
  auto get_kind() const { return Value.getKind(); }
  auto get_message() const { return Value.getMessage(); }
  auto get_text() const { return Value.getLineContents(); }
};

// Expr subclasses

class Expr : public ValueWithState<llvm::MCExpr*> {
public:
  using ValueWithState::ValueWithState;

  virtual ~Expr() = default;

  auto get_location() const { return wrap(State, Value->getLoc()); }
};

class SymbolRefExpr : public Expr {
public:
  using Expr::Expr;

  auto get_symbol() const {
    return wrap(State, &llvm::cast<llvm::MCSymbolRefExpr>(Value)->getSymbol());
  }
  auto get_variant_kind() const {
    return llvm::cast<llvm::MCSymbolRefExpr>(Value)->getKind();
  }

  auto get_raw_value() const {
    return llvm::cast<llvm::MCSymbolRefExpr>(Value);
  }
};

class ConstantExpr : public Expr {
public:
  using Expr::Expr;

  auto get_value() const {
    return llvm::cast<llvm::MCConstantExpr>(Value)->getValue();
  }
  auto get_size_in_bytes() const {
    return llvm::cast<llvm::MCConstantExpr>(Value)->getSizeInBytes();
  }
};

class BinaryExpr : public Expr {
public:
  using Expr::Expr;

  auto get_lhs() const {
    return wrap(State, llvm::cast<llvm::MCBinaryExpr>(Value)->getLHS());
  }
  auto get_rhs() const {
    return wrap(State, llvm::cast<llvm::MCBinaryExpr>(Value)->getRHS());
  }
  auto get_opcode() const {
    return llvm::cast<llvm::MCBinaryExpr>(Value)->getOpcode();
  }
};

class TargetExpr : public Expr {
public:
  using Expr::Expr;
};

class TargetExprAArch64 : public TargetExpr {
public:
  using TargetExpr::TargetExpr;

  auto get_sub_expr() const {
    return wrap(State, llvm::cast<llvm::AArch64MCExpr>(Value)->getSubExpr());
  }
  auto get_variant_kind_name() const {
    return llvm::cast<llvm::AArch64MCExpr>(Value)->getVariantKindName();
  }
};

class TargetExprMips : public TargetExpr {
public:
  using TargetExpr::TargetExpr;
};

// section subclasses

class Section : public ValueWithState<llvm::MCSection*> {
public:
  using ValueWithState::ValueWithState;
  virtual ~Section() = default;

  auto get_name() const { return Value->getName(); }
};

class SectionELF : public Section {
public:
  using Section::Section;

  auto get_type() const {
    return llvm::cast<llvm::MCSectionELF>(Value)->getType();
  }
  auto get_flags() const {
    return llvm::cast<llvm::MCSectionELF>(Value)->getFlags();
  }
};

class SectionCOFF : public Section {
public:
  using Section::Section;

  auto get_characteristics() const {
    return llvm::cast<llvm::MCSectionCOFF>(Value)->getCharacteristics();
  }
};

class SectionMachO : public Section {
public:
  using Section::Section;

  auto get_segment_name() const {
    return llvm::cast<llvm::MCSectionMachO>(Value)->getSegmentName();
  }
};

// module registration

void register_module(py::module& mcasm);

}; // namespace mc

#endif
