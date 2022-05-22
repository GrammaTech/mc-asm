from __future__ import annotations
import mcasm._core
import mcasm._core.mc as mc
import typing

__all__ = ["Assembler", "ParserState", "Streamer", "X86Syntax", "mc"]

class Assembler:
    def __init__(self, triple: str) -> None: ...
    def assemble(self, streamer: Streamer, asm: str) -> bool: ...
    @staticmethod
    def default_triple() -> str: ...
    @property
    def x86_syntax(self) -> X86Syntax:
        """
        :type: X86Syntax
        """
    @x86_syntax.setter
    def x86_syntax(self, arg1: X86Syntax) -> None:
        pass
    pass

class ParserState:
    @property
    def loc(self) -> mc.SourceLocation:
        """
        :type: mc.SourceLocation
        """
    pass

class Streamer:
    def __init__(self) -> None: ...
    def add_comment(
        self, state: ParserState, comment: str, eol: bool
    ) -> None: ...
    def add_explicit_comment(
        self, state: ParserState, comment: str
    ) -> None: ...
    def begin_coff_symbol_def(
        self, state: ParserState, symbol: mc.Symbol
    ) -> None: ...
    def change_section(
        self, state: ParserState, section: mc.Section, subsection: mc.Expr
    ) -> None: ...
    def diagnostic(self, state: ParserState, diag: mc.Diagnostic) -> None: ...
    def emit_absolute_symbol_diff(
        self, state: ParserState, hi: mc.Symbol, lo: mc.Symbol, size: int
    ) -> None: ...
    def emit_absolute_symbol_diff_as_uleb128(
        self, state: ParserState, hi: mc.Symbol, lo: mc.Symbol
    ) -> None: ...
    def emit_addrsig(self, state: ParserState) -> None: ...
    def emit_addrsig_sym(self, state: ParserState, sym: mc.Symbol) -> None: ...
    def emit_assembler_flag(
        self, state: ParserState, flag: mc.AssemblerFlag
    ) -> None: ...
    def emit_assignment(
        self, state: ParserState, symbol: mc.Symbol, value: mc.Expr
    ) -> None: ...
    def emit_binary_data(self, state: ParserState, data: bytes) -> None: ...
    def emit_bundle_align_mode(
        self, state: ParserState, align_pow_2: int
    ) -> None: ...
    def emit_bundle_lock(
        self, state: ParserState, align_to_end: bool
    ) -> None: ...
    def emit_bundle_unlock(self, state: ParserState) -> None: ...
    def emit_bytes(self, state: ParserState, data: bytes) -> None: ...
    def emit_cfi_adjust_cfa_offset(
        self, state: ParserState, adjustment: int
    ) -> None: ...
    def emit_cfi_b_key_frame(self, state: ParserState) -> None: ...
    def emit_cfi_def_cfa(
        self, state: ParserState, register: int, offset: int
    ) -> None: ...
    def emit_cfi_def_cfa_offset(
        self, state: ParserState, offset: int
    ) -> None: ...
    def emit_cfi_def_cfa_register(
        self, state: ParserState, register: int
    ) -> None: ...
    def emit_cfi_end_proc_impl(
        self, state: ParserState, cur_frame: mc.DwarfFrameInfo
    ) -> None: ...
    def emit_cfi_escape(self, state: ParserState, values: str) -> None: ...
    def emit_cfi_gnu_args_size(
        self, state: ParserState, size: int
    ) -> None: ...
    def emit_cfi_llvm_def_aspace_cfa(
        self,
        state: ParserState,
        register: int,
        offset: int,
        address_space: int,
    ) -> None: ...
    def emit_cfi_lsda(
        self, state: ParserState, sym: mc.Symbol, encoding: int
    ) -> None: ...
    def emit_cfi_negate_ra_state(self, state: ParserState) -> None: ...
    def emit_cfi_offset(
        self, state: ParserState, register: int, offset: int
    ) -> None: ...
    def emit_cfi_personality(
        self, state: ParserState, sym: mc.Symbol, encoding: int
    ) -> None: ...
    def emit_cfi_register(
        self, state: ParserState, register_1: int, register_2: int
    ) -> None: ...
    def emit_cfi_rel_offset(
        self, state: ParserState, register: int, offset: int
    ) -> None: ...
    def emit_cfi_remember_state(self, state: ParserState) -> None: ...
    def emit_cfi_restore(self, state: ParserState, register: int) -> None: ...
    def emit_cfi_restore_state(self, state: ParserState) -> None: ...
    def emit_cfi_return_column(
        self, state: ParserState, register: int
    ) -> None: ...
    def emit_cfi_same_value(
        self, state: ParserState, register: int
    ) -> None: ...
    def emit_cfi_sections(
        self, state: ParserState, eh: bool, debug: bool
    ) -> None: ...
    def emit_cfi_signal_frame(self, state: ParserState) -> None: ...
    def emit_cfi_start_proc_impl(
        self, state: ParserState, frame: mc.DwarfFrameInfo
    ) -> None: ...
    def emit_cfi_undefined(
        self, state: ParserState, register: int
    ) -> None: ...
    def emit_cfi_window_save(self, state: ParserState) -> None: ...
    def emit_cg_profile_entry(
        self,
        state: ParserState,
        from_: mc.SymbolRefExpr,
        to: mc.SymbolRefExpr,
        count: int,
    ) -> None: ...
    def emit_code_alignment(
        self, state: ParserState, byte_alignment: int, max_bytes_to_emit: int
    ) -> None: ...
    def emit_coff_imgprel32(
        self, state: ParserState, symbol: mc.Symbol, offset: int
    ) -> None: ...
    def emit_coff_safe_seh(
        self, state: ParserState, symbol: mc.Symbol
    ) -> None: ...
    def emit_coff_secprel32(
        self, state: ParserState, symbol: mc.Symbol, offset: int
    ) -> None: ...
    def emit_coff_section_index(
        self, state: ParserState, symbol: mc.Symbol
    ) -> None: ...
    def emit_coff_symbol_index(
        self, state: ParserState, symbol: mc.Symbol
    ) -> None: ...
    def emit_coff_symbol_storage_class(
        self, state: ParserState, storage_class: int
    ) -> None: ...
    def emit_coff_symbol_type(self, state: ParserState, type: int) -> None: ...
    def emit_common_symbol(
        self,
        state: ParserState,
        symbol: mc.Symbol,
        size: int,
        byte_alignment: int,
    ) -> None: ...
    def emit_cv_file_checksum_offset_directive(
        self, state: ParserState, file_no: int
    ) -> None: ...
    def emit_cv_file_checksums_directive(self, state: ParserState) -> None: ...
    def emit_cv_fpo_data(
        self, state: ParserState, proc_sym: mc.Symbol, loc: mc.SourceLocation
    ) -> None: ...
    def emit_cv_func_id_directive(
        self, state: ParserState, function_id: int
    ) -> bool: ...
    def emit_cv_inline_line_table_directive(
        self,
        state: ParserState,
        primary_function_id: int,
        source_file_id: int,
        source_line_num: int,
        fn_start_sym: mc.Symbol,
        fn_end_sym: mc.Symbol,
    ) -> None: ...
    def emit_cv_inline_site_id_directive(
        self,
        state: ParserState,
        function_id: int,
        ia_func: int,
        ia_file: int,
        ia_line: int,
        ia_col: int,
        loc: mc.SourceLocation,
    ) -> bool: ...
    def emit_cv_line_table_directive(
        self,
        state: ParserState,
        function_id: int,
        fn_start: mc.Symbol,
        fn_end: mc.Symbol,
    ) -> None: ...
    def emit_cv_loc_directive(
        self,
        state: ParserState,
        function_id: int,
        file_no: int,
        line: int,
        column: int,
        prologue_end: bool,
        is_stmt: bool,
        file_name: str,
        loc: mc.SourceLocation,
    ) -> None: ...
    def emit_cv_string_table_directive(self, state: ParserState) -> None: ...
    def emit_data_region(
        self, state: ParserState, kind: mc.DataRegionType
    ) -> None: ...
    def emit_dtprel32_value(
        self, state: ParserState, value: mc.Expr
    ) -> None: ...
    def emit_dtprel64_value(
        self, state: ParserState, value: mc.Expr
    ) -> None: ...
    def emit_dwarf_advance_line_addr(
        self,
        state: ParserState,
        line_delta: int,
        last_label: mc.Symbol,
        label: mc.Symbol,
        pointer_size: int,
    ) -> None: ...
    def emit_dwarf_line_end_entry(
        self, state: ParserState, section: mc.Section, last_label: mc.Symbol
    ) -> None: ...
    def emit_dwarf_line_start_label(
        self, state: ParserState, start_sym: mc.Symbol
    ) -> None: ...
    def emit_dwarf_loc_directive(
        self,
        state: ParserState,
        file_no: int,
        line: int,
        column: int,
        flags: int,
        isa: int,
        discriminator: int,
        file_name: str,
    ) -> None: ...
    def emit_eh_sym_attributes(
        self, state: ParserState, symbol: mc.Symbol, eh_symbol: mc.Symbol
    ) -> None: ...
    def emit_elf_size(
        self, state: ParserState, symbol: mc.Symbol, value: mc.Expr
    ) -> None: ...
    def emit_elf_symver_directive(
        self,
        state: ParserState,
        original_sym: mc.Symbol,
        name: str,
        keep_original_sym: bool,
    ) -> None: ...
    def emit_explicit_comments(self, state: ParserState) -> None: ...
    def emit_expr_fill(
        self,
        state: ParserState,
        num_values: mc.Expr,
        size: int,
        expr: int,
        loc: mc.SourceLocation,
    ) -> None: ...
    def emit_gnu_attribute(
        self, state: ParserState, tag: int, value: int
    ) -> None: ...
    def emit_gprel32_value(
        self, state: ParserState, value: mc.Expr
    ) -> None: ...
    def emit_gprel64_value(
        self, state: ParserState, value: mc.Expr
    ) -> None: ...
    def emit_ident(self, state: ParserState, ident_string: str) -> None: ...
    def emit_instruction(
        self,
        state: ParserState,
        inst: mc.Instruction,
        bytes: bytes,
        fixups: typing.List[mc.Fixup],
    ) -> None: ...
    def emit_int_value(
        self, state: ParserState, value: int, size: int
    ) -> None: ...
    def emit_int_value_in_hex(
        self, state: ParserState, value: int, size: int
    ) -> None: ...
    def emit_int_value_in_hex_with_padding(
        self, state: ParserState, value: int, size: int
    ) -> None: ...
    def emit_label(
        self, state: ParserState, symbol: mc.Symbol, loc: mc.SourceLocation
    ) -> None: ...
    def emit_linker_options(
        self, state: ParserState, kind: typing.List[str]
    ) -> None: ...
    def emit_local_common_symbol(
        self,
        state: ParserState,
        symbol: mc.Symbol,
        size: int,
        byte_alignment: int,
    ) -> None: ...
    def emit_nops(
        self,
        state: ParserState,
        num_bytes: int,
        controlled_nop_length: int,
        loc: mc.SourceLocation,
    ) -> None: ...
    def emit_raw_comment(
        self, state: ParserState, comment: str, tab_prefix: bool
    ) -> None: ...
    def emit_raw_text_impl(self, state: ParserState, string: str) -> None: ...
    def emit_sleb128_value(
        self, state: ParserState, value: mc.Expr
    ) -> None: ...
    def emit_symbol_attribute(
        self, state: ParserState, symbol: mc.Symbol, attribute: mc.SymbolAttr
    ) -> bool: ...
    def emit_symbol_desc(
        self, state: ParserState, symbol: mc.Symbol, desc_value: int
    ) -> None: ...
    def emit_syntax_directive(self, state: ParserState) -> None: ...
    def emit_tbss_symbol(
        self,
        state: ParserState,
        section: mc.Section,
        symbol: mc.Symbol,
        size: int,
        byte_alignment: int,
    ) -> None: ...
    def emit_thumb_func(self, state: ParserState, func: mc.Symbol) -> None: ...
    def emit_tprel32_value(
        self, state: ParserState, value: mc.Expr
    ) -> None: ...
    def emit_tprel64_value(
        self, state: ParserState, value: mc.Expr
    ) -> None: ...
    def emit_uleb128_value(
        self, state: ParserState, value: mc.Expr
    ) -> None: ...
    def emit_value_fill(
        self,
        state: ParserState,
        num_bytes: mc.Expr,
        fill_value: int,
        loc: mc.SourceLocation,
    ) -> None: ...
    def emit_value_impl(
        self,
        state: ParserState,
        value: mc.Expr,
        size: int,
        loc: mc.SourceLocation,
    ) -> None: ...
    def emit_value_to_alignment(
        self,
        state: ParserState,
        byte_alignment: int,
        value: int,
        value_size: int,
        max_bytes_to_emit: int,
    ) -> None: ...
    def emit_value_to_offset(
        self,
        state: ParserState,
        offset: mc.Expr,
        value: int,
        loc: mc.SourceLocation,
    ) -> None: ...
    def emit_weak_reference(
        self, state: ParserState, alias: mc.Symbol, symbol: mc.Symbol
    ) -> None: ...
    def emit_win_cfi_alloc_stack(
        self, state: ParserState, size: int, loc: mc.SourceLocation
    ) -> None: ...
    def emit_win_cfi_end_chained(
        self, state: ParserState, loc: mc.SourceLocation
    ) -> None: ...
    def emit_win_cfi_end_proc(
        self, state: ParserState, loc: mc.SourceLocation
    ) -> None: ...
    def emit_win_cfi_end_prolog(
        self, state: ParserState, loc: mc.SourceLocation
    ) -> None: ...
    def emit_win_cfi_funclet_or_func_end(
        self, state: ParserState, loc: mc.SourceLocation
    ) -> None: ...
    def emit_win_cfi_push_frame(
        self, state: ParserState, code: bool, loc: mc.SourceLocation
    ) -> None: ...
    def emit_win_cfi_push_reg(
        self, state: ParserState, register: mc.Register, loc: mc.SourceLocation
    ) -> None: ...
    def emit_win_cfi_save_reg(
        self,
        state: ParserState,
        register: mc.Register,
        offset: int,
        loc: mc.SourceLocation,
    ) -> None: ...
    def emit_win_cfi_save_xmm(
        self,
        state: ParserState,
        register: mc.Register,
        offset: int,
        loc: mc.SourceLocation,
    ) -> None: ...
    def emit_win_cfi_set_frame(
        self,
        state: ParserState,
        register: mc.Register,
        offset: int,
        loc: mc.SourceLocation,
    ) -> None: ...
    def emit_win_cfi_start_chained(
        self, state: ParserState, loc: mc.SourceLocation
    ) -> None: ...
    def emit_win_cfi_start_proc(
        self, state: ParserState, symbol: mc.Symbol, loc: mc.SourceLocation
    ) -> None: ...
    def emit_win_eh_handler(
        self,
        state: ParserState,
        sym: mc.Symbol,
        unwind: bool,
        except_: bool,
        loc: mc.SourceLocation,
    ) -> None: ...
    def emit_win_eh_handler_data(
        self, state: ParserState, loc: mc.SourceLocation
    ) -> None: ...
    def emit_xcoff_local_common_symbol(
        self,
        state: ParserState,
        label_sym: mc.Symbol,
        size: int,
        c_sect_sym: mc.Symbol,
        byte_alignment: int,
    ) -> None: ...
    def emit_xcoff_rename_directive(
        self, state: ParserState, name: mc.Symbol, rename: str
    ) -> None: ...
    def emit_xcoff_symbol_linkage_with_visibility(
        self,
        state: ParserState,
        symbol: mc.Symbol,
        linkage: mc.SymbolAttr,
        visibility: mc.SymbolAttr,
    ) -> None: ...
    def emit_zero_fill(
        self,
        state: ParserState,
        section: mc.Section,
        symbol: mc.Symbol,
        size: int,
        byte_alignment: int,
        loc: mc.SourceLocation,
    ) -> None: ...
    def end_coff_symbol_def(self, state: ParserState) -> None: ...
    def get_dwarf_line_table_symbol(
        self, state: ParserState, c_uid: int
    ) -> mc.Symbol: ...
    def init_sections(
        self, state: ParserState, no_exec_stack: bool
    ) -> None: ...
    pass

class X86Syntax:
    """
    Members:

      ATT

      INTEL
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
    ATT: mcasm._core.X86Syntax  # value = <X86Syntax.ATT: 0>
    INTEL: mcasm._core.X86Syntax  # value = <X86Syntax.INTEL: 1>
    __members__: dict  # value = {'ATT': <X86Syntax.ATT: 0>, 'INTEL': <X86Syntax.INTEL: 1>}
    pass
