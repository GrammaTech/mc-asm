"""Wrappers for LLVM MC classes"""
from __future__ import annotations
import mcasm._core.mc
import typing

__all__ = [
    "AssemblerFlag",
    "BinaryExpr",
    "ConstantExpr",
    "DataRegionType",
    "Diagnostic",
    "DwarfFrameInfo",
    "Expr",
    "Fixup",
    "FixupKindInfo",
    "Instruction",
    "InstructionDesc",
    "Register",
    "Section",
    "SectionCOFF",
    "SectionELF",
    "SectionMachO",
    "SourceLocation",
    "Symbol",
    "SymbolAttr",
    "SymbolRefExpr",
    "TargetExpr",
    "TargetExprAArch64",
    "TargetExprMips",
    "VersionMinType"
]


class AssemblerFlag():
    """
    Members:

      SyntaxUnified

      SubsectionsViaSymbols

      Code16

      Code32

      Code64
    """
    def __eq__(self, other: object) -> bool: ...
    def __getstate__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __index__(self) -> int: ...
    def __init__(self, value: int) -> None: ...
    def __int__(self) -> int: ...
    def __ne__(self, other: object) -> bool: ...
    def __repr__(self) -> str: ...
    def __setstate__(self, state: int) -> None: ...
    @property
    def name(self) -> str:
        """
        :type: str
        """
    @property
    def value(self) -> int:
        """
        :type: int
        """
    Code16: mcasm._core.mc.AssemblerFlag # value = <AssemblerFlag.Code16: 2>
    Code32: mcasm._core.mc.AssemblerFlag # value = <AssemblerFlag.Code32: 3>
    Code64: mcasm._core.mc.AssemblerFlag # value = <AssemblerFlag.Code64: 4>
    SubsectionsViaSymbols: mcasm._core.mc.AssemblerFlag # value = <AssemblerFlag.SubsectionsViaSymbols: 1>
    SyntaxUnified: mcasm._core.mc.AssemblerFlag # value = <AssemblerFlag.SyntaxUnified: 0>
    __members__: dict # value = {'SyntaxUnified': <AssemblerFlag.SyntaxUnified: 0>, 'SubsectionsViaSymbols': <AssemblerFlag.SubsectionsViaSymbols: 1>, 'Code16': <AssemblerFlag.Code16: 2>, 'Code32': <AssemblerFlag.Code32: 3>, 'Code64': <AssemblerFlag.Code64: 4>}
    pass
class Expr():
    @property
    def location(self) -> SourceLocation:
        """
        :type: SourceLocation
        """
    pass
class ConstantExpr(Expr):
    @property
    def size_in_bytes(self) -> int:
        """
        :type: int
        """
    @property
    def value(self) -> int:
        """
        :type: int
        """
    pass
class DataRegionType():
    """
    Members:

      DataRegion

      DataRegionJT8

      DataRegionJT16

      DataRegionJT32

      DataRegionEnd
    """
    def __eq__(self, other: object) -> bool: ...
    def __getstate__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __index__(self) -> int: ...
    def __init__(self, value: int) -> None: ...
    def __int__(self) -> int: ...
    def __ne__(self, other: object) -> bool: ...
    def __repr__(self) -> str: ...
    def __setstate__(self, state: int) -> None: ...
    @property
    def name(self) -> str:
        """
        :type: str
        """
    @property
    def value(self) -> int:
        """
        :type: int
        """
    DataRegion: mcasm._core.mc.DataRegionType # value = <DataRegionType.DataRegion: 0>
    DataRegionEnd: mcasm._core.mc.DataRegionType # value = <DataRegionType.DataRegionEnd: 4>
    DataRegionJT16: mcasm._core.mc.DataRegionType # value = <DataRegionType.DataRegionJT16: 2>
    DataRegionJT32: mcasm._core.mc.DataRegionType # value = <DataRegionType.DataRegionJT32: 3>
    DataRegionJT8: mcasm._core.mc.DataRegionType # value = <DataRegionType.DataRegionJT8: 1>
    __members__: dict # value = {'DataRegion': <DataRegionType.DataRegion: 0>, 'DataRegionJT8': <DataRegionType.DataRegionJT8: 1>, 'DataRegionJT16': <DataRegionType.DataRegionJT16: 2>, 'DataRegionJT32': <DataRegionType.DataRegionJT32: 3>, 'DataRegionEnd': <DataRegionType.DataRegionEnd: 4>}
    pass
class Diagnostic():
    class Kind():
        """
        Members:

          Error

          Warning

          Remark

          Note
        """
        def __eq__(self, other: object) -> bool: ...
        def __getstate__(self) -> int: ...
        def __hash__(self) -> int: ...
        def __index__(self) -> int: ...
        def __init__(self, value: int) -> None: ...
        def __int__(self) -> int: ...
        def __ne__(self, other: object) -> bool: ...
        def __repr__(self) -> str: ...
        def __setstate__(self, state: int) -> None: ...
        @property
        def name(self) -> str:
            """
            :type: str
            """
        @property
        def value(self) -> int:
            """
            :type: int
            """
        Error: mcasm._core.mc.Diagnostic.Kind # value = <Kind.Error: 0>
        Note: mcasm._core.mc.Diagnostic.Kind # value = <Kind.Note: 3>
        Remark: mcasm._core.mc.Diagnostic.Kind # value = <Kind.Remark: 2>
        Warning: mcasm._core.mc.Diagnostic.Kind # value = <Kind.Warning: 1>
        __members__: dict # value = {'Error': <Kind.Error: 0>, 'Warning': <Kind.Warning: 1>, 'Remark': <Kind.Remark: 2>, 'Note': <Kind.Note: 3>}
        pass
    @property
    def kind(self) -> Diagnostic.Kind:
        """
        :type: Diagnostic.Kind
        """
    @property
    def lineno(self) -> int:
        """
        :type: int
        """
    @property
    def message(self) -> str:
        """
        :type: str
        """
    @property
    def offset(self) -> int:
        """
        :type: int
        """
    @property
    def text(self) -> str:
        """
        :type: str
        """
    pass
class DwarfFrameInfo():
    pass
class BinaryExpr(Expr):
    class Opcode():
        """
        Members:

          Add

          And

          Div

          EQ

          GT

          GTE

          LAnd

          LOr

          LT

          LTE

          Mod

          Mul

          NE

          Or

          OrNot

          Shl

          AShr

          LShr

          Sub

          Xor
        """
        def __eq__(self, other: object) -> bool: ...
        def __getstate__(self) -> int: ...
        def __hash__(self) -> int: ...
        def __index__(self) -> int: ...
        def __init__(self, value: int) -> None: ...
        def __int__(self) -> int: ...
        def __ne__(self, other: object) -> bool: ...
        def __repr__(self) -> str: ...
        def __setstate__(self, state: int) -> None: ...
        @property
        def name(self) -> str:
            """
            :type: str
            """
        @property
        def value(self) -> int:
            """
            :type: int
            """
        AShr: mcasm._core.mc.BinaryExpr.Opcode # value = <Opcode.AShr: 16>
        Add: mcasm._core.mc.BinaryExpr.Opcode # value = <Opcode.Add: 0>
        And: mcasm._core.mc.BinaryExpr.Opcode # value = <Opcode.And: 1>
        Div: mcasm._core.mc.BinaryExpr.Opcode # value = <Opcode.Div: 2>
        EQ: mcasm._core.mc.BinaryExpr.Opcode # value = <Opcode.EQ: 3>
        GT: mcasm._core.mc.BinaryExpr.Opcode # value = <Opcode.GT: 4>
        GTE: mcasm._core.mc.BinaryExpr.Opcode # value = <Opcode.GTE: 5>
        LAnd: mcasm._core.mc.BinaryExpr.Opcode # value = <Opcode.LAnd: 6>
        LOr: mcasm._core.mc.BinaryExpr.Opcode # value = <Opcode.LOr: 7>
        LShr: mcasm._core.mc.BinaryExpr.Opcode # value = <Opcode.LShr: 17>
        LT: mcasm._core.mc.BinaryExpr.Opcode # value = <Opcode.LT: 8>
        LTE: mcasm._core.mc.BinaryExpr.Opcode # value = <Opcode.LTE: 9>
        Mod: mcasm._core.mc.BinaryExpr.Opcode # value = <Opcode.Mod: 10>
        Mul: mcasm._core.mc.BinaryExpr.Opcode # value = <Opcode.Mul: 11>
        NE: mcasm._core.mc.BinaryExpr.Opcode # value = <Opcode.NE: 12>
        Or: mcasm._core.mc.BinaryExpr.Opcode # value = <Opcode.Or: 13>
        OrNot: mcasm._core.mc.BinaryExpr.Opcode # value = <Opcode.OrNot: 14>
        Shl: mcasm._core.mc.BinaryExpr.Opcode # value = <Opcode.Shl: 15>
        Sub: mcasm._core.mc.BinaryExpr.Opcode # value = <Opcode.Sub: 18>
        Xor: mcasm._core.mc.BinaryExpr.Opcode # value = <Opcode.Xor: 19>
        __members__: dict # value = {'Add': <Opcode.Add: 0>, 'And': <Opcode.And: 1>, 'Div': <Opcode.Div: 2>, 'EQ': <Opcode.EQ: 3>, 'GT': <Opcode.GT: 4>, 'GTE': <Opcode.GTE: 5>, 'LAnd': <Opcode.LAnd: 6>, 'LOr': <Opcode.LOr: 7>, 'LT': <Opcode.LT: 8>, 'LTE': <Opcode.LTE: 9>, 'Mod': <Opcode.Mod: 10>, 'Mul': <Opcode.Mul: 11>, 'NE': <Opcode.NE: 12>, 'Or': <Opcode.Or: 13>, 'OrNot': <Opcode.OrNot: 14>, 'Shl': <Opcode.Shl: 15>, 'AShr': <Opcode.AShr: 16>, 'LShr': <Opcode.LShr: 17>, 'Sub': <Opcode.Sub: 18>, 'Xor': <Opcode.Xor: 19>}
        pass
    @property
    def lhs(self) -> Expr:
        """
        :type: Expr
        """
    @property
    def opcode(self) -> BinaryExpr.Opcode:
        """
        :type: BinaryExpr.Opcode
        """
    @property
    def rhs(self) -> Expr:
        """
        :type: Expr
        """
    pass
class Fixup():
    @property
    def kind_info(self) -> FixupKindInfo:
        """
        :type: FixupKindInfo
        """
    @property
    def offset(self) -> int:
        """
        :type: int
        """
    @property
    def value(self) -> Expr:
        """
        :type: Expr
        """
    pass
class FixupKindInfo():
    @property
    def bit_offset(self) -> int:
        """
        :type: int
        """
    @property
    def bit_size(self) -> int:
        """
        :type: int
        """
    @property
    def is_aligned_down_to_32_bits(self) -> int:
        """
        :type: int
        """
    @property
    def is_constant(self) -> int:
        """
        :type: int
        """
    @property
    def is_pc_rel(self) -> int:
        """
        :type: int
        """
    @property
    def is_target_dependent(self) -> int:
        """
        :type: int
        """
    @property
    def name(self) -> str:
        """
        :type: str
        """
    pass
class Instruction():
    @property
    def desc(self) -> InstructionDesc:
        """
        :type: InstructionDesc
        """
    @property
    def name(self) -> str:
        """
        :type: str
        """
    @property
    def opcode(self) -> int:
        """
        :type: int
        """
    @property
    def operands(self) -> typing.List[object]:
        """
        :type: typing.List[object]
        """
    pass
class InstructionDesc():
    @property
    def can_fold_as_load(self) -> bool:
        """
        :type: bool
        """
    @property
    def has_delay_slot(self) -> bool:
        """
        :type: bool
        """
    @property
    def has_optional_def(self) -> bool:
        """
        :type: bool
        """
    @property
    def has_unmodeled_side_effects(self) -> bool:
        """
        :type: bool
        """
    @property
    def implicit_defs(self) -> typing.List[Register]:
        """
        :type: typing.List[Register]
        """
    @property
    def implicit_uses(self) -> typing.List[Register]:
        """
        :type: typing.List[Register]
        """
    @property
    def is_add(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_authenticated(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_barrier(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_bitcast(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_branch(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_call(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_compare(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_conditional_branch(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_convergent(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_extract_subreg_like(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_indirect_branch(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_insert_subreg_like(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_move_immediate(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_move_reg(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_not_duplicable(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_predicable(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_pseudo(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_reg_sequence_like(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_return(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_select(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_terminator(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_trap(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_unconditional_branch(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_variadic(self) -> bool:
        """
        :type: bool
        """
    @property
    def may_load(self) -> bool:
        """
        :type: bool
        """
    @property
    def may_raise_fp_exception(self) -> bool:
        """
        :type: bool
        """
    @property
    def may_store(self) -> bool:
        """
        :type: bool
        """
    @property
    def variadic_ops_are_defs(self) -> bool:
        """
        :type: bool
        """
    pass
class Register():
    @property
    def id(self) -> int:
        """
        :type: int
        """
    @property
    def is_physical_register(self) -> bool:
        """
        :type: bool
        """
    @property
    def is_stack_slot(self) -> bool:
        """
        :type: bool
        """
    @property
    def name(self) -> str:
        """
        :type: str
        """
    pass
class Section():
    @property
    def name(self) -> str:
        """
        :type: str
        """
    pass
class SectionCOFF(Section):
    @property
    def characteristics(self) -> int:
        """
        :type: int
        """
    pass
class SectionELF(Section):
    @property
    def flags(self) -> int:
        """
        :type: int
        """
    @property
    def type(self) -> int:
        """
        :type: int
        """
    pass
class SectionMachO(Section):
    @property
    def segment_name(self) -> str:
        """
        :type: str
        """
    pass
class SourceLocation():
    def __iter__(self) -> typing.Iterator: ...
    def __str__(self) -> str: ...
    @property
    def lineno(self) -> int:
        """
        :type: int
        """
    @property
    def offset(self) -> int:
        """
        :type: int
        """
    pass
class Symbol():
    @property
    def is_temporary(self) -> bool:
        """
        :type: bool
        """
    @property
    def name(self) -> str:
        """
        :type: str
        """
    pass
class SymbolAttr():
    """
    Members:

      Cold

      ELF_TypeFunction

      ELF_TypeIndFunction

      ELF_TypeObject

      ELF_TypeTLS

      ELF_TypeCommon

      ELF_TypeNoType

      ELF_TypeGnuUniqueObject

      Global

      LGlobal

      Hidden

      IndirectSymbol

      Internal

      LazyReference

      Local

      NoDeadStrip

      SymbolResolver

      AltEntry

      PrivateExtern

      Protected

      Reference

      Weak

      WeakDefinition

      WeakReference

      WeakDefAutoPrivate
    """
    def __eq__(self, other: object) -> bool: ...
    def __getstate__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __index__(self) -> int: ...
    def __init__(self, value: int) -> None: ...
    def __int__(self) -> int: ...
    def __ne__(self, other: object) -> bool: ...
    def __repr__(self) -> str: ...
    def __setstate__(self, state: int) -> None: ...
    @property
    def name(self) -> str:
        """
        :type: str
        """
    @property
    def value(self) -> int:
        """
        :type: int
        """
    AltEntry: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.AltEntry: 19>
    Cold: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.Cold: 1>
    ELF_TypeCommon: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.ELF_TypeCommon: 6>
    ELF_TypeFunction: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.ELF_TypeFunction: 2>
    ELF_TypeGnuUniqueObject: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.ELF_TypeGnuUniqueObject: 8>
    ELF_TypeIndFunction: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.ELF_TypeIndFunction: 3>
    ELF_TypeNoType: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.ELF_TypeNoType: 7>
    ELF_TypeObject: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.ELF_TypeObject: 4>
    ELF_TypeTLS: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.ELF_TypeTLS: 5>
    Global: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.Global: 9>
    Hidden: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.Hidden: 12>
    IndirectSymbol: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.IndirectSymbol: 13>
    Internal: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.Internal: 14>
    LGlobal: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.LGlobal: 10>
    LazyReference: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.LazyReference: 15>
    Local: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.Local: 16>
    NoDeadStrip: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.NoDeadStrip: 17>
    PrivateExtern: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.PrivateExtern: 20>
    Protected: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.Protected: 21>
    Reference: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.Reference: 22>
    SymbolResolver: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.SymbolResolver: 18>
    Weak: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.Weak: 23>
    WeakDefAutoPrivate: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.WeakDefAutoPrivate: 26>
    WeakDefinition: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.WeakDefinition: 24>
    WeakReference: mcasm._core.mc.SymbolAttr # value = <SymbolAttr.WeakReference: 25>
    __members__: dict # value = {'Cold': <SymbolAttr.Cold: 1>, 'ELF_TypeFunction': <SymbolAttr.ELF_TypeFunction: 2>, 'ELF_TypeIndFunction': <SymbolAttr.ELF_TypeIndFunction: 3>, 'ELF_TypeObject': <SymbolAttr.ELF_TypeObject: 4>, 'ELF_TypeTLS': <SymbolAttr.ELF_TypeTLS: 5>, 'ELF_TypeCommon': <SymbolAttr.ELF_TypeCommon: 6>, 'ELF_TypeNoType': <SymbolAttr.ELF_TypeNoType: 7>, 'ELF_TypeGnuUniqueObject': <SymbolAttr.ELF_TypeGnuUniqueObject: 8>, 'Global': <SymbolAttr.Global: 9>, 'LGlobal': <SymbolAttr.LGlobal: 10>, 'Hidden': <SymbolAttr.Hidden: 12>, 'IndirectSymbol': <SymbolAttr.IndirectSymbol: 13>, 'Internal': <SymbolAttr.Internal: 14>, 'LazyReference': <SymbolAttr.LazyReference: 15>, 'Local': <SymbolAttr.Local: 16>, 'NoDeadStrip': <SymbolAttr.NoDeadStrip: 17>, 'SymbolResolver': <SymbolAttr.SymbolResolver: 18>, 'AltEntry': <SymbolAttr.AltEntry: 19>, 'PrivateExtern': <SymbolAttr.PrivateExtern: 20>, 'Protected': <SymbolAttr.Protected: 21>, 'Reference': <SymbolAttr.Reference: 22>, 'Weak': <SymbolAttr.Weak: 23>, 'WeakDefinition': <SymbolAttr.WeakDefinition: 24>, 'WeakReference': <SymbolAttr.WeakReference: 25>, 'WeakDefAutoPrivate': <SymbolAttr.WeakDefAutoPrivate: 26>}
    pass
class SymbolRefExpr(Expr):
    class VariantKind():
        """
        Members:

          None_

          Invalid

          GOT

          GOTOFF

          GOTREL

          PCREL

          GOTPCREL

          GOTTPOFF

          INDNTPOFF

          NTPOFF

          GOTNTPOFF

          PLT

          TLSGD

          TLSLD

          TLSLDM

          TPOFF

          DTPOFF

          TLSCALL

          TLSDESC

          TLVP

          TLVPPAGE

          TLVPPAGEOFF

          PAGE

          PAGEOFF

          GOTPAGE

          GOTPAGEOFF

          SECREL

          SIZE

          WEAKREF

          X86_ABS8

          X86_PLTOFF

          ARM_NONE

          ARM_GOT_PREL

          ARM_TARGET1

          ARM_TARGET2

          ARM_PREL31

          ARM_SBREL

          ARM_TLSLDO

          ARM_TLSDESCSEQ

          AVR_NONE

          AVR_LO8

          AVR_HI8

          AVR_HLO8

          AVR_DIFF8

          AVR_DIFF16

          AVR_DIFF32

          AVR_PM

          PPC_LO

          PPC_HI

          PPC_HA

          PPC_HIGH

          PPC_HIGHA

          PPC_HIGHER

          PPC_HIGHERA

          PPC_HIGHEST

          PPC_HIGHESTA

          PPC_GOT_LO

          PPC_GOT_HI

          PPC_GOT_HA

          PPC_TOCBASE

          PPC_TOC

          PPC_TOC_LO

          PPC_TOC_HI

          PPC_TOC_HA

          PPC_U

          PPC_L

          PPC_DTPMOD

          PPC_TPREL_LO

          PPC_TPREL_HI

          PPC_TPREL_HA

          PPC_TPREL_HIGH

          PPC_TPREL_HIGHA

          PPC_TPREL_HIGHER

          PPC_TPREL_HIGHERA

          PPC_TPREL_HIGHEST

          PPC_TPREL_HIGHESTA

          PPC_DTPREL_LO

          PPC_DTPREL_HI

          PPC_DTPREL_HA

          PPC_DTPREL_HIGH

          PPC_DTPREL_HIGHA

          PPC_DTPREL_HIGHER

          PPC_DTPREL_HIGHERA

          PPC_DTPREL_HIGHEST

          PPC_DTPREL_HIGHESTA

          PPC_GOT_TPREL

          PPC_GOT_TPREL_LO

          PPC_GOT_TPREL_HI

          PPC_GOT_TPREL_HA

          PPC_GOT_DTPREL

          PPC_GOT_DTPREL_LO

          PPC_GOT_DTPREL_HI

          PPC_GOT_DTPREL_HA

          PPC_TLS

          PPC_GOT_TLSGD

          PPC_GOT_TLSGD_LO

          PPC_GOT_TLSGD_HI

          PPC_GOT_TLSGD_HA

          PPC_TLSGD

          PPC_AIX_TLSGD

          PPC_AIX_TLSGDM

          PPC_GOT_TLSLD

          PPC_GOT_TLSLD_LO

          PPC_GOT_TLSLD_HI

          PPC_GOT_TLSLD_HA

          PPC_GOT_PCREL

          PPC_GOT_TLSGD_PCREL

          PPC_GOT_TLSLD_PCREL

          PPC_GOT_TPREL_PCREL

          PPC_TLS_PCREL

          PPC_TLSLD

          PPC_LOCAL

          PPC_NOTOC

          PPC_PCREL_OPT

          COFF_IMGREL32

          Hexagon_LO16

          Hexagon_HI16

          Hexagon_GPREL

          Hexagon_GD_GOT

          Hexagon_LD_GOT

          Hexagon_GD_PLT

          Hexagon_LD_PLT

          Hexagon_IE

          Hexagon_IE_GOT

          WASM_TYPEINDEX

          WASM_TLSREL

          WASM_MBREL

          WASM_TBREL

          AMDGPU_GOTPCREL32_LO

          AMDGPU_GOTPCREL32_HI

          AMDGPU_REL32_LO

          AMDGPU_REL32_HI

          AMDGPU_REL64

          AMDGPU_ABS32_LO

          AMDGPU_ABS32_HI

          VE_HI32

          VE_LO32

          VE_PC_HI32

          VE_PC_LO32

          VE_GOT_HI32

          VE_GOT_LO32

          VE_GOTOFF_HI32

          VE_GOTOFF_LO32

          VE_PLT_HI32

          VE_PLT_LO32

          VE_TLS_GD_HI32

          VE_TLS_GD_LO32

          VE_TPOFF_HI32

          VE_TPOFF_LO32

          TPREL

          DTPREL
        """
        def __eq__(self, other: object) -> bool: ...
        def __getstate__(self) -> int: ...
        def __hash__(self) -> int: ...
        def __index__(self) -> int: ...
        def __init__(self, value: int) -> None: ...
        def __int__(self) -> int: ...
        def __ne__(self, other: object) -> bool: ...
        def __repr__(self) -> str: ...
        def __setstate__(self, state: int) -> None: ...
        @property
        def name(self) -> str:
            """
            :type: str
            """
        @property
        def value(self) -> int:
            """
            :type: int
            """
        AMDGPU_ABS32_HI: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.AMDGPU_ABS32_HI: 134>
        AMDGPU_ABS32_LO: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.AMDGPU_ABS32_LO: 133>
        AMDGPU_GOTPCREL32_HI: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.AMDGPU_GOTPCREL32_HI: 129>
        AMDGPU_GOTPCREL32_LO: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.AMDGPU_GOTPCREL32_LO: 128>
        AMDGPU_REL32_HI: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.AMDGPU_REL32_HI: 131>
        AMDGPU_REL32_LO: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.AMDGPU_REL32_LO: 130>
        AMDGPU_REL64: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.AMDGPU_REL64: 132>
        ARM_GOT_PREL: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.ARM_GOT_PREL: 32>
        ARM_NONE: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.ARM_NONE: 31>
        ARM_PREL31: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.ARM_PREL31: 35>
        ARM_SBREL: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.ARM_SBREL: 36>
        ARM_TARGET1: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.ARM_TARGET1: 33>
        ARM_TARGET2: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.ARM_TARGET2: 34>
        ARM_TLSDESCSEQ: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.ARM_TLSDESCSEQ: 38>
        ARM_TLSLDO: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.ARM_TLSLDO: 37>
        AVR_DIFF16: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.AVR_DIFF16: 44>
        AVR_DIFF32: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.AVR_DIFF32: 45>
        AVR_DIFF8: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.AVR_DIFF8: 43>
        AVR_HI8: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.AVR_HI8: 41>
        AVR_HLO8: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.AVR_HLO8: 42>
        AVR_LO8: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.AVR_LO8: 40>
        AVR_NONE: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.AVR_NONE: 39>
        AVR_PM: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.AVR_PM: 46>
        COFF_IMGREL32: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.COFF_IMGREL32: 114>
        DTPOFF: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.DTPOFF: 16>
        DTPREL: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.DTPREL: 150>
        GOT: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.GOT: 2>
        GOTNTPOFF: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.GOTNTPOFF: 10>
        GOTOFF: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.GOTOFF: 3>
        GOTPAGE: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.GOTPAGE: 24>
        GOTPAGEOFF: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.GOTPAGEOFF: 25>
        GOTPCREL: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.GOTPCREL: 6>
        GOTREL: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.GOTREL: 4>
        GOTTPOFF: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.GOTTPOFF: 7>
        Hexagon_GD_GOT: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.Hexagon_GD_GOT: 118>
        Hexagon_GD_PLT: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.Hexagon_GD_PLT: 120>
        Hexagon_GPREL: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.Hexagon_GPREL: 117>
        Hexagon_HI16: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.Hexagon_HI16: 116>
        Hexagon_IE: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.Hexagon_IE: 122>
        Hexagon_IE_GOT: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.Hexagon_IE_GOT: 123>
        Hexagon_LD_GOT: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.Hexagon_LD_GOT: 119>
        Hexagon_LD_PLT: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.Hexagon_LD_PLT: 121>
        Hexagon_LO16: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.Hexagon_LO16: 115>
        INDNTPOFF: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.INDNTPOFF: 8>
        Invalid: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.Invalid: 1>
        NTPOFF: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.NTPOFF: 9>
        None_: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.None_: 0>
        PAGE: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PAGE: 22>
        PAGEOFF: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PAGEOFF: 23>
        PCREL: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PCREL: 5>
        PLT: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PLT: 11>
        PPC_AIX_TLSGD: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_AIX_TLSGD: 99>
        PPC_AIX_TLSGDM: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_AIX_TLSGDM: 100>
        PPC_DTPMOD: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_DTPMOD: 66>
        PPC_DTPREL_HA: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_DTPREL_HA: 78>
        PPC_DTPREL_HI: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_DTPREL_HI: 77>
        PPC_DTPREL_HIGH: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_DTPREL_HIGH: 79>
        PPC_DTPREL_HIGHA: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_DTPREL_HIGHA: 80>
        PPC_DTPREL_HIGHER: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_DTPREL_HIGHER: 81>
        PPC_DTPREL_HIGHERA: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_DTPREL_HIGHERA: 82>
        PPC_DTPREL_HIGHEST: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_DTPREL_HIGHEST: 83>
        PPC_DTPREL_HIGHESTA: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_DTPREL_HIGHESTA: 84>
        PPC_DTPREL_LO: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_DTPREL_LO: 76>
        PPC_GOT_DTPREL: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_DTPREL: 89>
        PPC_GOT_DTPREL_HA: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_DTPREL_HA: 92>
        PPC_GOT_DTPREL_HI: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_DTPREL_HI: 91>
        PPC_GOT_DTPREL_LO: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_DTPREL_LO: 90>
        PPC_GOT_HA: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_HA: 58>
        PPC_GOT_HI: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_HI: 57>
        PPC_GOT_LO: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_LO: 56>
        PPC_GOT_PCREL: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_PCREL: 105>
        PPC_GOT_TLSGD: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_TLSGD: 94>
        PPC_GOT_TLSGD_HA: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_TLSGD_HA: 97>
        PPC_GOT_TLSGD_HI: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_TLSGD_HI: 96>
        PPC_GOT_TLSGD_LO: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_TLSGD_LO: 95>
        PPC_GOT_TLSGD_PCREL: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_TLSGD_PCREL: 106>
        PPC_GOT_TLSLD: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_TLSLD: 101>
        PPC_GOT_TLSLD_HA: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_TLSLD_HA: 104>
        PPC_GOT_TLSLD_HI: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_TLSLD_HI: 103>
        PPC_GOT_TLSLD_LO: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_TLSLD_LO: 102>
        PPC_GOT_TLSLD_PCREL: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_TLSLD_PCREL: 107>
        PPC_GOT_TPREL: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_TPREL: 85>
        PPC_GOT_TPREL_HA: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_TPREL_HA: 88>
        PPC_GOT_TPREL_HI: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_TPREL_HI: 87>
        PPC_GOT_TPREL_LO: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_TPREL_LO: 86>
        PPC_GOT_TPREL_PCREL: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_GOT_TPREL_PCREL: 108>
        PPC_HA: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_HA: 49>
        PPC_HI: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_HI: 48>
        PPC_HIGH: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_HIGH: 50>
        PPC_HIGHA: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_HIGHA: 51>
        PPC_HIGHER: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_HIGHER: 52>
        PPC_HIGHERA: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_HIGHERA: 53>
        PPC_HIGHEST: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_HIGHEST: 54>
        PPC_HIGHESTA: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_HIGHESTA: 55>
        PPC_L: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_L: 65>
        PPC_LO: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_LO: 47>
        PPC_LOCAL: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_LOCAL: 111>
        PPC_NOTOC: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_NOTOC: 112>
        PPC_PCREL_OPT: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_PCREL_OPT: 113>
        PPC_TLS: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_TLS: 93>
        PPC_TLSGD: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_TLSGD: 98>
        PPC_TLSLD: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_TLSLD: 110>
        PPC_TLS_PCREL: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_TLS_PCREL: 109>
        PPC_TOC: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_TOC: 60>
        PPC_TOCBASE: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_TOCBASE: 59>
        PPC_TOC_HA: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_TOC_HA: 63>
        PPC_TOC_HI: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_TOC_HI: 62>
        PPC_TOC_LO: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_TOC_LO: 61>
        PPC_TPREL_HA: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_TPREL_HA: 69>
        PPC_TPREL_HI: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_TPREL_HI: 68>
        PPC_TPREL_HIGH: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_TPREL_HIGH: 70>
        PPC_TPREL_HIGHA: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_TPREL_HIGHA: 71>
        PPC_TPREL_HIGHER: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_TPREL_HIGHER: 72>
        PPC_TPREL_HIGHERA: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_TPREL_HIGHERA: 73>
        PPC_TPREL_HIGHEST: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_TPREL_HIGHEST: 74>
        PPC_TPREL_HIGHESTA: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_TPREL_HIGHESTA: 75>
        PPC_TPREL_LO: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_TPREL_LO: 67>
        PPC_U: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.PPC_U: 64>
        SECREL: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.SECREL: 26>
        SIZE: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.SIZE: 27>
        TLSCALL: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.TLSCALL: 17>
        TLSDESC: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.TLSDESC: 18>
        TLSGD: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.TLSGD: 12>
        TLSLD: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.TLSLD: 13>
        TLSLDM: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.TLSLDM: 14>
        TLVP: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.TLVP: 19>
        TLVPPAGE: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.TLVPPAGE: 20>
        TLVPPAGEOFF: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.TLVPPAGEOFF: 21>
        TPOFF: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.TPOFF: 15>
        TPREL: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.TPREL: 149>
        VE_GOTOFF_HI32: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.VE_GOTOFF_HI32: 141>
        VE_GOTOFF_LO32: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.VE_GOTOFF_LO32: 142>
        VE_GOT_HI32: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.VE_GOT_HI32: 139>
        VE_GOT_LO32: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.VE_GOT_LO32: 140>
        VE_HI32: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.VE_HI32: 135>
        VE_LO32: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.VE_LO32: 136>
        VE_PC_HI32: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.VE_PC_HI32: 137>
        VE_PC_LO32: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.VE_PC_LO32: 138>
        VE_PLT_HI32: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.VE_PLT_HI32: 143>
        VE_PLT_LO32: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.VE_PLT_LO32: 144>
        VE_TLS_GD_HI32: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.VE_TLS_GD_HI32: 145>
        VE_TLS_GD_LO32: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.VE_TLS_GD_LO32: 146>
        VE_TPOFF_HI32: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.VE_TPOFF_HI32: 147>
        VE_TPOFF_LO32: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.VE_TPOFF_LO32: 148>
        WASM_MBREL: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.WASM_MBREL: 126>
        WASM_TBREL: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.WASM_TBREL: 127>
        WASM_TLSREL: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.WASM_TLSREL: 125>
        WASM_TYPEINDEX: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.WASM_TYPEINDEX: 124>
        WEAKREF: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.WEAKREF: 28>
        X86_ABS8: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.X86_ABS8: 29>
        X86_PLTOFF: mcasm._core.mc.SymbolRefExpr.VariantKind # value = <VariantKind.X86_PLTOFF: 30>
        __members__: dict # value = {'None_': <VariantKind.None_: 0>, 'Invalid': <VariantKind.Invalid: 1>, 'GOT': <VariantKind.GOT: 2>, 'GOTOFF': <VariantKind.GOTOFF: 3>, 'GOTREL': <VariantKind.GOTREL: 4>, 'PCREL': <VariantKind.PCREL: 5>, 'GOTPCREL': <VariantKind.GOTPCREL: 6>, 'GOTTPOFF': <VariantKind.GOTTPOFF: 7>, 'INDNTPOFF': <VariantKind.INDNTPOFF: 8>, 'NTPOFF': <VariantKind.NTPOFF: 9>, 'GOTNTPOFF': <VariantKind.GOTNTPOFF: 10>, 'PLT': <VariantKind.PLT: 11>, 'TLSGD': <VariantKind.TLSGD: 12>, 'TLSLD': <VariantKind.TLSLD: 13>, 'TLSLDM': <VariantKind.TLSLDM: 14>, 'TPOFF': <VariantKind.TPOFF: 15>, 'DTPOFF': <VariantKind.DTPOFF: 16>, 'TLSCALL': <VariantKind.TLSCALL: 17>, 'TLSDESC': <VariantKind.TLSDESC: 18>, 'TLVP': <VariantKind.TLVP: 19>, 'TLVPPAGE': <VariantKind.TLVPPAGE: 20>, 'TLVPPAGEOFF': <VariantKind.TLVPPAGEOFF: 21>, 'PAGE': <VariantKind.PAGE: 22>, 'PAGEOFF': <VariantKind.PAGEOFF: 23>, 'GOTPAGE': <VariantKind.GOTPAGE: 24>, 'GOTPAGEOFF': <VariantKind.GOTPAGEOFF: 25>, 'SECREL': <VariantKind.SECREL: 26>, 'SIZE': <VariantKind.SIZE: 27>, 'WEAKREF': <VariantKind.WEAKREF: 28>, 'X86_ABS8': <VariantKind.X86_ABS8: 29>, 'X86_PLTOFF': <VariantKind.X86_PLTOFF: 30>, 'ARM_NONE': <VariantKind.ARM_NONE: 31>, 'ARM_GOT_PREL': <VariantKind.ARM_GOT_PREL: 32>, 'ARM_TARGET1': <VariantKind.ARM_TARGET1: 33>, 'ARM_TARGET2': <VariantKind.ARM_TARGET2: 34>, 'ARM_PREL31': <VariantKind.ARM_PREL31: 35>, 'ARM_SBREL': <VariantKind.ARM_SBREL: 36>, 'ARM_TLSLDO': <VariantKind.ARM_TLSLDO: 37>, 'ARM_TLSDESCSEQ': <VariantKind.ARM_TLSDESCSEQ: 38>, 'AVR_NONE': <VariantKind.AVR_NONE: 39>, 'AVR_LO8': <VariantKind.AVR_LO8: 40>, 'AVR_HI8': <VariantKind.AVR_HI8: 41>, 'AVR_HLO8': <VariantKind.AVR_HLO8: 42>, 'AVR_DIFF8': <VariantKind.AVR_DIFF8: 43>, 'AVR_DIFF16': <VariantKind.AVR_DIFF16: 44>, 'AVR_DIFF32': <VariantKind.AVR_DIFF32: 45>, 'AVR_PM': <VariantKind.AVR_PM: 46>, 'PPC_LO': <VariantKind.PPC_LO: 47>, 'PPC_HI': <VariantKind.PPC_HI: 48>, 'PPC_HA': <VariantKind.PPC_HA: 49>, 'PPC_HIGH': <VariantKind.PPC_HIGH: 50>, 'PPC_HIGHA': <VariantKind.PPC_HIGHA: 51>, 'PPC_HIGHER': <VariantKind.PPC_HIGHER: 52>, 'PPC_HIGHERA': <VariantKind.PPC_HIGHERA: 53>, 'PPC_HIGHEST': <VariantKind.PPC_HIGHEST: 54>, 'PPC_HIGHESTA': <VariantKind.PPC_HIGHESTA: 55>, 'PPC_GOT_LO': <VariantKind.PPC_GOT_LO: 56>, 'PPC_GOT_HI': <VariantKind.PPC_GOT_HI: 57>, 'PPC_GOT_HA': <VariantKind.PPC_GOT_HA: 58>, 'PPC_TOCBASE': <VariantKind.PPC_TOCBASE: 59>, 'PPC_TOC': <VariantKind.PPC_TOC: 60>, 'PPC_TOC_LO': <VariantKind.PPC_TOC_LO: 61>, 'PPC_TOC_HI': <VariantKind.PPC_TOC_HI: 62>, 'PPC_TOC_HA': <VariantKind.PPC_TOC_HA: 63>, 'PPC_U': <VariantKind.PPC_U: 64>, 'PPC_L': <VariantKind.PPC_L: 65>, 'PPC_DTPMOD': <VariantKind.PPC_DTPMOD: 66>, 'PPC_TPREL_LO': <VariantKind.PPC_TPREL_LO: 67>, 'PPC_TPREL_HI': <VariantKind.PPC_TPREL_HI: 68>, 'PPC_TPREL_HA': <VariantKind.PPC_TPREL_HA: 69>, 'PPC_TPREL_HIGH': <VariantKind.PPC_TPREL_HIGH: 70>, 'PPC_TPREL_HIGHA': <VariantKind.PPC_TPREL_HIGHA: 71>, 'PPC_TPREL_HIGHER': <VariantKind.PPC_TPREL_HIGHER: 72>, 'PPC_TPREL_HIGHERA': <VariantKind.PPC_TPREL_HIGHERA: 73>, 'PPC_TPREL_HIGHEST': <VariantKind.PPC_TPREL_HIGHEST: 74>, 'PPC_TPREL_HIGHESTA': <VariantKind.PPC_TPREL_HIGHESTA: 75>, 'PPC_DTPREL_LO': <VariantKind.PPC_DTPREL_LO: 76>, 'PPC_DTPREL_HI': <VariantKind.PPC_DTPREL_HI: 77>, 'PPC_DTPREL_HA': <VariantKind.PPC_DTPREL_HA: 78>, 'PPC_DTPREL_HIGH': <VariantKind.PPC_DTPREL_HIGH: 79>, 'PPC_DTPREL_HIGHA': <VariantKind.PPC_DTPREL_HIGHA: 80>, 'PPC_DTPREL_HIGHER': <VariantKind.PPC_DTPREL_HIGHER: 81>, 'PPC_DTPREL_HIGHERA': <VariantKind.PPC_DTPREL_HIGHERA: 82>, 'PPC_DTPREL_HIGHEST': <VariantKind.PPC_DTPREL_HIGHEST: 83>, 'PPC_DTPREL_HIGHESTA': <VariantKind.PPC_DTPREL_HIGHESTA: 84>, 'PPC_GOT_TPREL': <VariantKind.PPC_GOT_TPREL: 85>, 'PPC_GOT_TPREL_LO': <VariantKind.PPC_GOT_TPREL_LO: 86>, 'PPC_GOT_TPREL_HI': <VariantKind.PPC_GOT_TPREL_HI: 87>, 'PPC_GOT_TPREL_HA': <VariantKind.PPC_GOT_TPREL_HA: 88>, 'PPC_GOT_DTPREL': <VariantKind.PPC_GOT_DTPREL: 89>, 'PPC_GOT_DTPREL_LO': <VariantKind.PPC_GOT_DTPREL_LO: 90>, 'PPC_GOT_DTPREL_HI': <VariantKind.PPC_GOT_DTPREL_HI: 91>, 'PPC_GOT_DTPREL_HA': <VariantKind.PPC_GOT_DTPREL_HA: 92>, 'PPC_TLS': <VariantKind.PPC_TLS: 93>, 'PPC_GOT_TLSGD': <VariantKind.PPC_GOT_TLSGD: 94>, 'PPC_GOT_TLSGD_LO': <VariantKind.PPC_GOT_TLSGD_LO: 95>, 'PPC_GOT_TLSGD_HI': <VariantKind.PPC_GOT_TLSGD_HI: 96>, 'PPC_GOT_TLSGD_HA': <VariantKind.PPC_GOT_TLSGD_HA: 97>, 'PPC_TLSGD': <VariantKind.PPC_TLSGD: 98>, 'PPC_AIX_TLSGD': <VariantKind.PPC_AIX_TLSGD: 99>, 'PPC_AIX_TLSGDM': <VariantKind.PPC_AIX_TLSGDM: 100>, 'PPC_GOT_TLSLD': <VariantKind.PPC_GOT_TLSLD: 101>, 'PPC_GOT_TLSLD_LO': <VariantKind.PPC_GOT_TLSLD_LO: 102>, 'PPC_GOT_TLSLD_HI': <VariantKind.PPC_GOT_TLSLD_HI: 103>, 'PPC_GOT_TLSLD_HA': <VariantKind.PPC_GOT_TLSLD_HA: 104>, 'PPC_GOT_PCREL': <VariantKind.PPC_GOT_PCREL: 105>, 'PPC_GOT_TLSGD_PCREL': <VariantKind.PPC_GOT_TLSGD_PCREL: 106>, 'PPC_GOT_TLSLD_PCREL': <VariantKind.PPC_GOT_TLSLD_PCREL: 107>, 'PPC_GOT_TPREL_PCREL': <VariantKind.PPC_GOT_TPREL_PCREL: 108>, 'PPC_TLS_PCREL': <VariantKind.PPC_TLS_PCREL: 109>, 'PPC_TLSLD': <VariantKind.PPC_TLSLD: 110>, 'PPC_LOCAL': <VariantKind.PPC_LOCAL: 111>, 'PPC_NOTOC': <VariantKind.PPC_NOTOC: 112>, 'PPC_PCREL_OPT': <VariantKind.PPC_PCREL_OPT: 113>, 'COFF_IMGREL32': <VariantKind.COFF_IMGREL32: 114>, 'Hexagon_LO16': <VariantKind.Hexagon_LO16: 115>, 'Hexagon_HI16': <VariantKind.Hexagon_HI16: 116>, 'Hexagon_GPREL': <VariantKind.Hexagon_GPREL: 117>, 'Hexagon_GD_GOT': <VariantKind.Hexagon_GD_GOT: 118>, 'Hexagon_LD_GOT': <VariantKind.Hexagon_LD_GOT: 119>, 'Hexagon_GD_PLT': <VariantKind.Hexagon_GD_PLT: 120>, 'Hexagon_LD_PLT': <VariantKind.Hexagon_LD_PLT: 121>, 'Hexagon_IE': <VariantKind.Hexagon_IE: 122>, 'Hexagon_IE_GOT': <VariantKind.Hexagon_IE_GOT: 123>, 'WASM_TYPEINDEX': <VariantKind.WASM_TYPEINDEX: 124>, 'WASM_TLSREL': <VariantKind.WASM_TLSREL: 125>, 'WASM_MBREL': <VariantKind.WASM_MBREL: 126>, 'WASM_TBREL': <VariantKind.WASM_TBREL: 127>, 'AMDGPU_GOTPCREL32_LO': <VariantKind.AMDGPU_GOTPCREL32_LO: 128>, 'AMDGPU_GOTPCREL32_HI': <VariantKind.AMDGPU_GOTPCREL32_HI: 129>, 'AMDGPU_REL32_LO': <VariantKind.AMDGPU_REL32_LO: 130>, 'AMDGPU_REL32_HI': <VariantKind.AMDGPU_REL32_HI: 131>, 'AMDGPU_REL64': <VariantKind.AMDGPU_REL64: 132>, 'AMDGPU_ABS32_LO': <VariantKind.AMDGPU_ABS32_LO: 133>, 'AMDGPU_ABS32_HI': <VariantKind.AMDGPU_ABS32_HI: 134>, 'VE_HI32': <VariantKind.VE_HI32: 135>, 'VE_LO32': <VariantKind.VE_LO32: 136>, 'VE_PC_HI32': <VariantKind.VE_PC_HI32: 137>, 'VE_PC_LO32': <VariantKind.VE_PC_LO32: 138>, 'VE_GOT_HI32': <VariantKind.VE_GOT_HI32: 139>, 'VE_GOT_LO32': <VariantKind.VE_GOT_LO32: 140>, 'VE_GOTOFF_HI32': <VariantKind.VE_GOTOFF_HI32: 141>, 'VE_GOTOFF_LO32': <VariantKind.VE_GOTOFF_LO32: 142>, 'VE_PLT_HI32': <VariantKind.VE_PLT_HI32: 143>, 'VE_PLT_LO32': <VariantKind.VE_PLT_LO32: 144>, 'VE_TLS_GD_HI32': <VariantKind.VE_TLS_GD_HI32: 145>, 'VE_TLS_GD_LO32': <VariantKind.VE_TLS_GD_LO32: 146>, 'VE_TPOFF_HI32': <VariantKind.VE_TPOFF_HI32: 147>, 'VE_TPOFF_LO32': <VariantKind.VE_TPOFF_LO32: 148>, 'TPREL': <VariantKind.TPREL: 149>, 'DTPREL': <VariantKind.DTPREL: 150>}
        pass
    @property
    def symbol(self) -> Symbol:
        """
        :type: Symbol
        """
    @property
    def variant_kind(self) -> SymbolRefExpr.VariantKind:
        """
        :type: SymbolRefExpr.VariantKind
        """
    pass
class TargetExpr(Expr):
    pass
class TargetExprAArch64(TargetExpr, Expr):
    @property
    def sub_expr(self) -> Expr:
        """
        :type: Expr
        """
    @property
    def variant_kind_name(self) -> str:
        """
        :type: str
        """
    pass
class TargetExprMips(TargetExpr, Expr):
    pass
class VersionMinType():
    """
    Members:

      IOSVersionMin

      OSXVersionMin

      TvOSVersionMin

      WatchOSVersionMin
    """
    def __eq__(self, other: object) -> bool: ...
    def __getstate__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __index__(self) -> int: ...
    def __init__(self, value: int) -> None: ...
    def __int__(self) -> int: ...
    def __ne__(self, other: object) -> bool: ...
    def __repr__(self) -> str: ...
    def __setstate__(self, state: int) -> None: ...
    @property
    def name(self) -> str:
        """
        :type: str
        """
    @property
    def value(self) -> int:
        """
        :type: int
        """
    IOSVersionMin: mcasm._core.mc.VersionMinType # value = <VersionMinType.IOSVersionMin: 0>
    OSXVersionMin: mcasm._core.mc.VersionMinType # value = <VersionMinType.OSXVersionMin: 1>
    TvOSVersionMin: mcasm._core.mc.VersionMinType # value = <VersionMinType.TvOSVersionMin: 2>
    WatchOSVersionMin: mcasm._core.mc.VersionMinType # value = <VersionMinType.WatchOSVersionMin: 3>
    __members__: dict # value = {'IOSVersionMin': <VersionMinType.IOSVersionMin: 0>, 'OSXVersionMin': <VersionMinType.OSXVersionMin: 1>, 'TvOSVersionMin': <VersionMinType.TvOSVersionMin: 2>, 'WatchOSVersionMin': <VersionMinType.WatchOSVersionMin: 3>}
    pass
