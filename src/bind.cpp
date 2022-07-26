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
#include <memory>

#include "casters.h"
#include "mc.h"
#include "state.h"

// Not all MCStreamer virtual functions are implemented yet. This macro guards
// the stubs for them.
#define NOT_IMPLEMENTED 0

using namespace llvm;

static void InitLLVM() {
  InitializeAllAsmParsers();
  InitializeAllTargetInfos();
  InitializeAllTargetMCs();
}

enum class X86Syntax {
  ATT,
  INTEL,
};

class StreamerBase {
public:
  virtual ~StreamerBase() = default;

  virtual void
  emit_cfi_start_proc_impl(std::shared_ptr<ParserState> State,
                           std::shared_ptr<mc::DwarfFrameInfo> Frame) {
    null_check(Frame);
    State->Str->MCStreamer::emitCFIStartProcImpl(*unwrap(Frame));
    checkError();
  }

  virtual void
  emit_cfi_end_proc_impl(std::shared_ptr<ParserState> State,
                         std::shared_ptr<mc::DwarfFrameInfo> CurFrame) {
    null_check(CurFrame);
    State->Str->MCStreamer::emitCFIEndProcImpl(*unwrap(CurFrame));
    checkError();
  }

#if NOT_IMPLEMENTED
  virtual void emit_windows_unwind_tables(std::shared_ptr<ParserState> State, ? Frame) {
    State->Str->MCStreamer::EmitWindowsUnwindTables(?);
    checkError();
  }
#endif

  virtual void emit_windows_unwind_tables(std::shared_ptr<ParserState> State) {
    State->Str->MCStreamer::EmitWindowsUnwindTables();
    checkError();
  }

  virtual void emit_raw_text_impl(std::shared_ptr<ParserState> State,
                                  std::string_view String) {
    State->Str->MCStreamer::emitRawTextImpl(String);
    checkError();
  }

  virtual void add_comment(std::shared_ptr<ParserState> State,
                           std::string_view T, bool EOL) {
    State->Str->MCStreamer::AddComment(T, EOL);
    checkError();
  }

  virtual void emit_raw_comment(std::shared_ptr<ParserState> State,
                                std::string_view T, bool TabPrefix) {
    State->Str->MCStreamer::emitRawComment(T, TabPrefix);
    checkError();
  }

  virtual void add_explicit_comment(std::shared_ptr<ParserState> State,
                                    std::string_view T) {
    State->Str->MCStreamer::addExplicitComment(T);
    checkError();
  }

  virtual void emit_explicit_comments(std::shared_ptr<ParserState> State) {
    State->Str->MCStreamer::emitExplicitComments();
    checkError();
  }

  virtual void change_section(std::shared_ptr<ParserState> State,
                              std::shared_ptr<mc::Section> Section,
                              std::shared_ptr<mc::Expr> SubSection) {
    State->Str->MCStreamer::changeSection(unwrap(Section), unwrap(SubSection));
    checkError();
  }

  virtual void init_sections(std::shared_ptr<ParserState> State,
                             bool NoExecStack) {
    State->Str->MCStreamer::InitSections(NoExecStack);
    checkError();
  }

  virtual void emit_label(std::shared_ptr<ParserState> State,
                          std::shared_ptr<mc::Symbol> Symbol,
                          std::shared_ptr<mc::SourceLocation> Loc) {
    State->Str->MCStreamer::emitLabel(unwrap(Symbol), unwrap(Loc));
    checkError();
  }

  virtual void emit_eh_sym_attributes(std::shared_ptr<ParserState> State,
                                      std::shared_ptr<mc::Symbol> Symbol,
                                      std::shared_ptr<mc::Symbol> EHSymbol) {
    State->Str->MCStreamer::emitEHSymAttributes(unwrap(Symbol),
                                                unwrap(EHSymbol));
    checkError();
  }

  virtual void emit_assembler_flag(std::shared_ptr<ParserState> State,
                                   MCAssemblerFlag Flag) {
    State->Str->MCStreamer::emitAssemblerFlag(Flag);
    checkError();
  }

  virtual void emit_linker_options(std::shared_ptr<ParserState> State,
                                   std::vector<std::string>& Kind) {
    State->Str->MCStreamer::emitLinkerOptions(Kind);
    checkError();
  }

  virtual void emit_data_region(std::shared_ptr<ParserState> State,
                                MCDataRegionType Kind) {
    State->Str->MCStreamer::emitDataRegion(Kind);
    checkError();
  }

#if NOT_IMPLEMENTED
  virtual void emit_version_min(std::shared_ptr<ParserState> State, MCVersionMinType Type, unsigned Major, unsigned Minor, unsigned Update, ? SDKVersion) {
    State->Str->MCStreamer::emitVersionMin(Type, Major, Minor, Update, ?);
    checkError();
  }

  virtual void emit_build_version(std::shared_ptr<ParserState> State, unsigned Platform, unsigned Major, unsigned Minor, unsigned Update, ? SDKVersion) {
    State->Str->MCStreamer::emitBuildVersion(Platform, Major, Minor, Update, ?);
    checkError();
  }
#endif

  virtual void emit_thumb_func(std::shared_ptr<ParserState> State,
                               std::shared_ptr<mc::Symbol> Func) {
    State->Str->MCStreamer::emitThumbFunc(unwrap(Func));
    checkError();
  }

  virtual void emit_assignment(std::shared_ptr<ParserState> State,
                               std::shared_ptr<mc::Symbol> Symbol,
                               std::shared_ptr<mc::Expr> Value) {
    State->Str->MCStreamer::emitAssignment(unwrap(Symbol), unwrap(Value));
    checkError();
  }

  virtual void emit_weak_reference(std::shared_ptr<ParserState> State,
                                   std::shared_ptr<mc::Symbol> Alias,
                                   std::shared_ptr<mc::Symbol> Symbol) {
    State->Str->MCStreamer::emitWeakReference(unwrap(Alias), unwrap(Symbol));
    checkError();
  }

  virtual bool emit_symbol_attribute(std::shared_ptr<ParserState> State,
                                     std::shared_ptr<mc::Symbol> Symbol,
                                     MCSymbolAttr Attribute) {
    // emitSymbolAttribute is pure virtual, nothing to invoke here
    return true;
  }

  virtual void emit_symbol_desc(std::shared_ptr<ParserState> State,
                                std::shared_ptr<mc::Symbol> Symbol,
                                unsigned DescValue) {
    State->Str->MCStreamer::emitSymbolDesc(unwrap(Symbol), DescValue);
    checkError();
  }

  virtual void begin_coff_symbol_def(std::shared_ptr<ParserState> State,
                                     std::shared_ptr<mc::Symbol> Symbol) {
    State->Str->MCStreamer::BeginCOFFSymbolDef(unwrap(Symbol));
    checkError();
  }

  virtual void
  emit_coff_symbol_storage_class(std::shared_ptr<ParserState> State,
                                 int StorageClass) {
    State->Str->MCStreamer::EmitCOFFSymbolStorageClass(StorageClass);
    checkError();
  }

  virtual void emit_coff_symbol_type(std::shared_ptr<ParserState> State,
                                     int Type) {
    State->Str->MCStreamer::EmitCOFFSymbolType(Type);
    checkError();
  }

  virtual void end_coff_symbol_def(std::shared_ptr<ParserState> State) {
    State->Str->MCStreamer::EndCOFFSymbolDef();
    checkError();
  }

  virtual void emit_coff_safe_seh(std::shared_ptr<ParserState> State,
                                  std::shared_ptr<mc::Symbol> Symbol) {
    State->Str->MCStreamer::EmitCOFFSafeSEH(unwrap(Symbol));
    checkError();
  }

  virtual void emit_coff_symbol_index(std::shared_ptr<ParserState> State,
                                      std::shared_ptr<mc::Symbol> Symbol) {
    State->Str->MCStreamer::EmitCOFFSymbolIndex(unwrap(Symbol));
    checkError();
  }

  virtual void emit_coff_section_index(std::shared_ptr<ParserState> State,
                                       std::shared_ptr<mc::Symbol> Symbol) {
    State->Str->MCStreamer::EmitCOFFSectionIndex(unwrap(Symbol));
    checkError();
  }

  virtual void emit_coff_secprel32(std::shared_ptr<ParserState> State,
                                   std::shared_ptr<mc::Symbol> Symbol,
                                   uint64_t Offset) {
    State->Str->MCStreamer::EmitCOFFSecRel32(unwrap(Symbol), Offset);
    checkError();
  }

  virtual void emit_coff_imgprel32(std::shared_ptr<ParserState> State,
                                   std::shared_ptr<mc::Symbol> Symbol,
                                   int64_t Offset) {
    State->Str->MCStreamer::EmitCOFFImgRel32(unwrap(Symbol), Offset);
    checkError();
  }

  virtual void emit_xcoff_local_common_symbol(
      std::shared_ptr<ParserState> State, std::shared_ptr<mc::Symbol> LabelSym,
      uint64_t Size, std::shared_ptr<mc::Symbol> CsectSym,
      unsigned ByteAlignment) {
    State->Str->MCStreamer::emitXCOFFLocalCommonSymbol(
        unwrap(LabelSym), Size, unwrap(CsectSym), ByteAlignment);
    checkError();
  }

  virtual void emit_xcoff_symbol_linkage_with_visibility(
      std::shared_ptr<ParserState> State, std::shared_ptr<mc::Symbol> Symbol,
      MCSymbolAttr Linkage, MCSymbolAttr Visibility) {
    State->Str->MCStreamer::emitXCOFFSymbolLinkageWithVisibility(
        unwrap(Symbol), Linkage, Visibility);
    checkError();
  }

  virtual void emit_xcoff_rename_directive(std::shared_ptr<ParserState> State,
                                           std::shared_ptr<mc::Symbol> Name,
                                           std::string_view Rename) {
    State->Str->MCStreamer::emitXCOFFRenameDirective(unwrap(Name), Rename);
    checkError();
  }

  virtual void emit_elf_size(std::shared_ptr<ParserState> State,
                             std::shared_ptr<mc::Symbol> Symbol,
                             std::shared_ptr<mc::Expr> Value) {
    State->Str->MCStreamer::emitELFSize(unwrap(Symbol), unwrap(Value));
    checkError();
  }

  virtual void
  emit_elf_symver_directive(std::shared_ptr<ParserState> State,
                            std::shared_ptr<mc::Symbol> OriginalSym,
                            std::string_view Name, bool KeepOriginalSym) {
    State->Str->MCStreamer::emitELFSymverDirective(unwrap(OriginalSym), Name,
                                                   KeepOriginalSym);
    checkError();
  }

#if NOT_IMPLEMENTED
  virtual void emit_loh_directive(std::shared_ptr<ParserState> State,
                                  MCLOHType Kind,
                                  std::shared_ptr<mc::LOHArgs> Args) {
    State->Str->MCStreamer::emitLOHDirective(unwrap(Kind), unwrap(Args));
    checkError();
  }
#endif

  virtual void emit_gnu_attribute(std::shared_ptr<ParserState> State,
                                  unsigned Tag, unsigned Value) {
    State->Str->MCStreamer::emitGNUAttribute(Tag, Value);
    checkError();
  }

  virtual void emit_common_symbol(std::shared_ptr<ParserState> State,
                                  std::shared_ptr<mc::Symbol> Symbol,
                                  uint64_t Size, unsigned ByteAlignment) {
    // emitCommonSymbol is pure virtual, nothing to invoke here
  }

  virtual void emit_local_common_symbol(std::shared_ptr<ParserState> State,
                                        std::shared_ptr<mc::Symbol> Symbol,
                                        uint64_t Size, unsigned ByteAlignment) {
    State->Str->MCStreamer::emitLocalCommonSymbol(unwrap(Symbol), Size,
                                                  ByteAlignment);
    checkError();
  }

  virtual void emit_zero_fill(std::shared_ptr<ParserState> State,
                              std::shared_ptr<mc::Section> Section,
                              std::shared_ptr<mc::Symbol> Symbol, uint64_t Size,
                              unsigned ByteAlignment,
                              std::shared_ptr<mc::SourceLocation> Loc) {
    // emitZeroFill is pure virtual, nothing to invoke here
    checkError();
  }

  virtual void emit_tbss_symbol(std::shared_ptr<ParserState> State,
                                std::shared_ptr<mc::Section> Section,
                                std::shared_ptr<mc::Symbol> Symbol,
                                uint64_t Size, unsigned ByteAlignment) {
    State->Str->MCStreamer::emitTBSSSymbol(unwrap(Section), unwrap(Symbol),
                                           Size, ByteAlignment);
    checkError();
  }

  virtual void emit_bytes(std::shared_ptr<ParserState> State, py::bytes Data) {
    State->Str->MCStreamer::emitBytes(static_cast<std::string_view>(Data));
    checkError();
  }

  virtual void emit_binary_data(std::shared_ptr<ParserState> State,
                                py::bytes Data) {
    State->Str->MCStreamer::emitBinaryData(static_cast<std::string_view>(Data));
    checkError();
  }

  virtual void emit_value_impl(std::shared_ptr<ParserState> State,
                               std::shared_ptr<mc::Expr> Value, unsigned Size,
                               std::shared_ptr<mc::SourceLocation> Loc) {
    State->Str->MCStreamer::emitValueImpl(unwrap(Value), Size, unwrap(Loc));
    checkError();
  }

  virtual void emit_int_value(std::shared_ptr<ParserState> State,
                              uint64_t Value, unsigned Size) {
    State->Str->MCStreamer::emitIntValue(Value, Size);
    checkError();
  }

#if NOT_IMPLEMENTED
  virtual void emit_int_value(std::shared_ptr<ParserState> State, ? Value) {
    State->Str->MCStreamer::emitIntValue(?);
    checkError();
  }
#endif

  virtual void emit_int_value_in_hex(std::shared_ptr<ParserState> State,
                                     uint64_t Value, unsigned Size) {
    State->Str->MCStreamer::emitIntValueInHex(Value, Size);
    checkError();
  }

  virtual void
  emit_int_value_in_hex_with_padding(std::shared_ptr<ParserState> State,
                                     uint64_t Value, unsigned Size) {
    State->Str->MCStreamer::emitIntValueInHexWithPadding(Value, Size);
    checkError();
  }

  virtual void emit_uleb128_value(std::shared_ptr<ParserState> State,
                                  std::shared_ptr<mc::Expr> Value) {
    State->Str->MCStreamer::emitULEB128Value(unwrap(Value));
    checkError();
  }

  virtual void emit_sleb128_value(std::shared_ptr<ParserState> State,
                                  std::shared_ptr<mc::Expr> Value) {
    State->Str->MCStreamer::emitSLEB128Value(unwrap(Value));
    checkError();
  }

  virtual void emit_dtprel64_value(std::shared_ptr<ParserState> State,
                                   std::shared_ptr<mc::Expr> Value) {
    State->Str->MCStreamer::emitDTPRel64Value(unwrap(Value));
    checkError();
  }

  virtual void emit_dtprel32_value(std::shared_ptr<ParserState> State,
                                   std::shared_ptr<mc::Expr> Value) {
    State->Str->MCStreamer::emitDTPRel32Value(unwrap(Value));
    checkError();
  }

  virtual void emit_tprel64_value(std::shared_ptr<ParserState> State,
                                  std::shared_ptr<mc::Expr> Value) {
    State->Str->MCStreamer::emitTPRel64Value(unwrap(Value));
    checkError();
  }

  virtual void emit_tprel32_value(std::shared_ptr<ParserState> State,
                                  std::shared_ptr<mc::Expr> Value) {
    State->Str->MCStreamer::emitTPRel32Value(unwrap(Value));
    checkError();
  }

  virtual void emit_gprel64_value(std::shared_ptr<ParserState> State,
                                  std::shared_ptr<mc::Expr> Value) {
    State->Str->MCStreamer::emitGPRel64Value(unwrap(Value));
    checkError();
  }

  virtual void emit_gprel32_value(std::shared_ptr<ParserState> State,
                                  std::shared_ptr<mc::Expr> Value) {
    State->Str->MCStreamer::emitGPRel32Value(unwrap(Value));
    checkError();
  }

  virtual void emit_value_fill(std::shared_ptr<ParserState> State,
                               std::shared_ptr<mc::Expr> NumBytes,
                               uint64_t FillValue,
                               std::shared_ptr<mc::SourceLocation> Loc) {
    null_check(NumBytes);
    State->Str->MCStreamer::emitFill(*unwrap(NumBytes), FillValue, unwrap(Loc));
    checkError();
  }

  virtual void emit_expr_fill(std::shared_ptr<ParserState> State,
                              std::shared_ptr<mc::Expr> NumValues, int64_t Size,
                              int64_t Expr,
                              std::shared_ptr<mc::SourceLocation> Loc) {
    null_check(NumValues);
    State->Str->MCStreamer::emitFill(*unwrap(NumValues), Size, Expr,
                                     unwrap(Loc));
    checkError();
  }

  virtual void emit_nops(std::shared_ptr<ParserState> State, int64_t NumBytes,
                         int64_t ControlledNopLength,
                         std::shared_ptr<mc::SourceLocation> Loc) {
    State->Str->MCStreamer::emitNops(NumBytes, ControlledNopLength,
                                     unwrap(Loc));
    checkError();
  }

  virtual void emit_value_to_alignment(std::shared_ptr<ParserState> State,
                                       unsigned ByteAlignment, int64_t Value,
                                       unsigned ValueSize,
                                       unsigned MaxBytesToEmit) {
    State->Str->MCStreamer::emitValueToAlignment(ByteAlignment, Value,
                                                 ValueSize, MaxBytesToEmit);
    checkError();
  }

  virtual void emit_code_alignment(std::shared_ptr<ParserState> State,
                                   unsigned ByteAlignment,
                                   unsigned MaxBytesToEmit) {
    State->Str->MCStreamer::emitCodeAlignment(ByteAlignment, MaxBytesToEmit);
    checkError();
  }

  virtual void emit_value_to_offset(std::shared_ptr<ParserState> State,
                                    std::shared_ptr<mc::Expr> Offset,
                                    unsigned char Value,
                                    std::shared_ptr<mc::SourceLocation> Loc) {
    State->Str->MCStreamer::emitValueToOffset(unwrap(Offset), Value,
                                              unwrap(Loc));
    checkError();
  }

  virtual void emit_file_directive(std::shared_ptr<ParserState> State,
                                   std::string_view Filename) {
    State->Str->MCStreamer::emitFileDirective(Filename);
    checkError();
  }

  virtual void emit_file_directive(std::shared_ptr<ParserState> State,
                                   std::string_view Filename,
                                   std::string_view CompilerVerion,
                                   std::string_view TimeStamp,
                                   std::string_view Description) {
    State->Str->MCStreamer::emitFileDirective(Filename, CompilerVerion,
                                              TimeStamp, Description);
    checkError();
  }

  virtual void emit_ident(std::shared_ptr<ParserState> State,
                          std::string_view IdentString) {
    State->Str->MCStreamer::emitIdent(IdentString);
    checkError();
  }

#if NOT_IMPLEMENTED
  virtual void try_emit_dwarf_file_directive(std::shared_ptr<ParserState> State, unsigned FileNo, std::string_view Directory, std::string_view Filename, ? Checksum, ? Source, unsigned CUID) {
    auto Result = State->Str->MCStreamer::tryEmitDwarfFileDirective(FileNo, Directory, Filename, ?, ?, CUID);
    checkError();
    return Result;
  }

  virtual void emit_dwarf_file_0_directive(std::shared_ptr<ParserState> State, std::string_view Directory, std::string_view Filename, ? Checksum, ? Source, unsigned CUID) {
    State->Str->MCStreamer::emitDwarfFile0Directive(Directory, Filename, ?, ?, CUID);
    checkError();
  }
#endif

  virtual void emit_cfi_b_key_frame(std::shared_ptr<ParserState> State) {
    State->Str->MCStreamer::emitCFIBKeyFrame();
    checkError();
  }

  virtual void emit_dwarf_loc_directive(std::shared_ptr<ParserState> State,
                                        unsigned FileNo, unsigned Line,
                                        unsigned Column, unsigned Flags,
                                        unsigned Isa, unsigned Discriminator,
                                        std::string_view FileName) {
    State->Str->MCStreamer::emitDwarfLocDirective(FileNo, Line, Column, Flags,
                                                  Isa, Discriminator, FileName);
    checkError();
  }

#if NOT_IMPLEMENTED
  virtual void emit_cv_file_directive(std::shared_ptr<ParserState> State, unsigned FileNo, std::string_view Filename, ? Checksum, unsigned ChecksumKind) {
    return State->Str->MCStreamer::EmitCVFileDirective(FileNo, Filename, ?, ChecksumKind);
    checkError();
  }
#endif

  virtual bool emit_cv_func_id_directive(std::shared_ptr<ParserState> State,
                                         unsigned FunctionId) {
    auto Result = State->Str->MCStreamer::EmitCVFuncIdDirective(FunctionId);
    checkError();
    return Result;
  }

  virtual bool emit_cv_inline_site_id_directive(
      std::shared_ptr<ParserState> State, unsigned FunctionId, unsigned IAFunc,
      unsigned IAFile, unsigned IALine, unsigned IACol,
      std::shared_ptr<mc::SourceLocation> Loc) {
    auto Result = State->Str->MCStreamer::EmitCVInlineSiteIdDirective(
        FunctionId, IAFunc, IAFile, IALine, IACol, unwrap(Loc));
    checkError();
    return Result;
  }

  virtual void emit_cv_loc_directive(std::shared_ptr<ParserState> State,
                                     unsigned FunctionId, unsigned FileNo,
                                     unsigned Line, unsigned Column,
                                     bool PrologueEnd, bool IsStmt,
                                     std::string_view FileName,
                                     std::shared_ptr<mc::SourceLocation> Loc) {
    State->Str->MCStreamer::emitCVLocDirective(FunctionId, FileNo, Line, Column,
                                               PrologueEnd, IsStmt, FileName,
                                               unwrap(Loc));
    checkError();
  }

  virtual void emit_cv_line_table_directive(std::shared_ptr<ParserState> State,
                                            unsigned FunctionId,
                                            std::shared_ptr<mc::Symbol> FnStart,
                                            std::shared_ptr<mc::Symbol> FnEnd) {
    State->Str->MCStreamer::emitCVLinetableDirective(
        FunctionId, unwrap(FnStart), unwrap(FnEnd));
    checkError();
  }

  virtual void emit_cv_inline_line_table_directive(
      std::shared_ptr<ParserState> State, unsigned PrimaryFunctionId,
      unsigned SourceFileId, unsigned SourceLineNum,
      std::shared_ptr<mc::Symbol> FnStartSym,
      std::shared_ptr<mc::Symbol> FnEndSym) {
    State->Str->MCStreamer::emitCVInlineLinetableDirective(
        PrimaryFunctionId, SourceFileId, SourceLineNum, unwrap(FnStartSym),
        unwrap(FnEndSym));
    checkError();
  }

#if NOT_IMPLEMENTED
  virtual void emit_cv_def_range_directive(std::shared_ptr<ParserState> State, ? Ranges, std::string_view FixedSizePortion) {
    State->Str->MCStreamer::emitCVDefRangeDirective(?, FixedSizePortion);
    checkError();
  }

  virtual void emit_cv_def_range_directive(std::shared_ptr<ParserState> State, ? Ranges, ? DRHdr) {
    State->Str->MCStreamer::emitCVDefRangeDirective(?, ?);
    checkError();
  }

  virtual void emit_cv_def_range_directive(std::shared_ptr<ParserState> State, ? Ranges, ? DRHdr) {
    State->Str->MCStreamer::emitCVDefRangeDirective(?, ?);
    checkError();
  }

  virtual void emit_cv_def_range_directive(std::shared_ptr<ParserState> State, ? Ranges, ? DRHdr) {
    State->Str->MCStreamer::emitCVDefRangeDirective(?, ?);
    checkError();
  }

  virtual void emit_cv_def_range_directive(std::shared_ptr<ParserState> State, ? Ranges, ? DRHdr) {
    State->Str->MCStreamer::emitCVDefRangeDirective(?, ?);
    checkError();
  }
#endif

  virtual void
  emit_cv_string_table_directive(std::shared_ptr<ParserState> State) {
    State->Str->MCStreamer::emitCVStringTableDirective();
    checkError();
  }

  virtual void
  emit_cv_file_checksums_directive(std::shared_ptr<ParserState> State) {
    State->Str->MCStreamer::emitCVFileChecksumsDirective();
    checkError();
  }

  virtual void
  emit_cv_file_checksum_offset_directive(std::shared_ptr<ParserState> State,
                                         unsigned FileNo) {
    State->Str->MCStreamer::emitCVFileChecksumOffsetDirective(FileNo);
    checkError();
  }

  virtual void emit_cv_fpo_data(std::shared_ptr<ParserState> State,
                                std::shared_ptr<mc::Symbol> ProcSym,
                                std::shared_ptr<mc::SourceLocation> Loc) {
    State->Str->MCStreamer::EmitCVFPOData(unwrap(ProcSym), unwrap(Loc));
    checkError();
  }

  virtual void emit_absolute_symbol_diff(std::shared_ptr<ParserState> State,
                                         std::shared_ptr<mc::Symbol> Hi,
                                         std::shared_ptr<mc::Symbol> Lo,
                                         unsigned Size) {
    State->Str->MCStreamer::emitAbsoluteSymbolDiff(unwrap(Hi), unwrap(Lo),
                                                   Size);
    checkError();
  }

  virtual void
  emit_absolute_symbol_diff_as_uleb128(std::shared_ptr<ParserState> State,
                                       std::shared_ptr<mc::Symbol> Hi,
                                       std::shared_ptr<mc::Symbol> Lo) {
    State->Str->MCStreamer::emitAbsoluteSymbolDiffAsULEB128(unwrap(Hi),
                                                            unwrap(Lo));
    checkError();
  }

  virtual std::shared_ptr<mc::Symbol>
  get_dwarf_line_table_symbol(std::shared_ptr<ParserState> State,
                              unsigned CUID) {
    auto Result =
        mc::wrap(State, State->Str->MCStreamer::getDwarfLineTableSymbol(CUID));
    checkError();
    return Result;
  }

  virtual void emit_cfi_sections(std::shared_ptr<ParserState> State, bool EH,
                                 bool Debug) {
    State->Str->MCStreamer::emitCFISections(EH, Debug);
    checkError();
  }

  virtual void emit_cfi_def_cfa(std::shared_ptr<ParserState> State,
                                int64_t Register, int64_t Offset) {
    State->Str->MCStreamer::emitCFIDefCfa(Register, Offset);
    checkError();
  }

  virtual void emit_cfi_def_cfa_offset(std::shared_ptr<ParserState> State,
                                       int64_t Offset) {
    State->Str->MCStreamer::emitCFIDefCfaOffset(Offset);
    checkError();
  }

  virtual void emit_cfi_def_cfa_register(std::shared_ptr<ParserState> State,
                                         int64_t Register) {
    State->Str->MCStreamer::emitCFIDefCfaRegister(Register);
    checkError();
  }

  virtual void emit_cfi_llvm_def_aspace_cfa(std::shared_ptr<ParserState> State,
                                            int64_t Register, int64_t Offset,
                                            int64_t AddressSpace) {
    State->Str->MCStreamer::emitCFILLVMDefAspaceCfa(Register, Offset,
                                                    AddressSpace);
    checkError();
  }

  virtual void emit_cfi_offset(std::shared_ptr<ParserState> State,
                               int64_t Register, int64_t Offset) {
    State->Str->MCStreamer::emitCFIOffset(Register, Offset);
    checkError();
  }

  virtual void emit_cfi_personality(std::shared_ptr<ParserState> State,
                                    std::shared_ptr<mc::Symbol> Sym,
                                    unsigned Encoding) {
    State->Str->MCStreamer::emitCFIPersonality(unwrap(Sym), Encoding);
    checkError();
  }

  virtual void emit_cfi_lsda(std::shared_ptr<ParserState> State,
                             std::shared_ptr<mc::Symbol> Sym,
                             unsigned Encoding) {
    State->Str->MCStreamer::emitCFILsda(unwrap(Sym), Encoding);
    checkError();
  }

  virtual void emit_cfi_remember_state(std::shared_ptr<ParserState> State) {
    State->Str->MCStreamer::emitCFIRememberState();
    checkError();
  }

  virtual void emit_cfi_restore_state(std::shared_ptr<ParserState> State) {
    State->Str->MCStreamer::emitCFIRestoreState();
    checkError();
  }

  virtual void emit_cfi_same_value(std::shared_ptr<ParserState> State,
                                   int64_t Register) {
    State->Str->MCStreamer::emitCFISameValue(Register);
    checkError();
  }

  virtual void emit_cfi_restore(std::shared_ptr<ParserState> State,
                                int64_t Register) {
    State->Str->MCStreamer::emitCFIRestore(Register);
    checkError();
  }

  virtual void emit_cfi_rel_offset(std::shared_ptr<ParserState> State,
                                   int64_t Register, int64_t Offset) {
    State->Str->MCStreamer::emitCFIRelOffset(Register, Offset);
    checkError();
  }

  virtual void emit_cfi_adjust_cfa_offset(std::shared_ptr<ParserState> State,
                                          int64_t Adjustment) {
    State->Str->MCStreamer::emitCFIAdjustCfaOffset(Adjustment);
    checkError();
  }

  virtual void emit_cfi_escape(std::shared_ptr<ParserState> State,
                               std::string_view Values) {
    State->Str->MCStreamer::emitCFIEscape(Values);
    checkError();
  }

  virtual void emit_cfi_return_column(std::shared_ptr<ParserState> State,
                                      int64_t Register) {
    State->Str->MCStreamer::emitCFIReturnColumn(Register);
    checkError();
  }

  virtual void emit_cfi_gnu_args_size(std::shared_ptr<ParserState> State,
                                      int64_t Size) {
    State->Str->MCStreamer::emitCFIGnuArgsSize(Size);
    checkError();
  }

  virtual void emit_cfi_signal_frame(std::shared_ptr<ParserState> State) {
    State->Str->MCStreamer::emitCFISignalFrame();
    checkError();
  }

  virtual void emit_cfi_undefined(std::shared_ptr<ParserState> State,
                                  int64_t Register) {
    State->Str->MCStreamer::emitCFIUndefined(Register);
    checkError();
  }

  virtual void emit_cfi_register(std::shared_ptr<ParserState> State,
                                 int64_t Register1, int64_t Register2) {
    State->Str->MCStreamer::emitCFIRegister(Register1, Register2);
    checkError();
  }

  virtual void emit_cfi_window_save(std::shared_ptr<ParserState> State) {
    State->Str->MCStreamer::emitCFIWindowSave();
    checkError();
  }

  virtual void emit_cfi_negate_ra_state(std::shared_ptr<ParserState> State) {
    State->Str->MCStreamer::emitCFINegateRAState();
    checkError();
  }

  virtual void
  emit_win_cfi_start_proc(std::shared_ptr<ParserState> State,
                          std::shared_ptr<mc::Symbol> Symbol,
                          std::shared_ptr<mc::SourceLocation> Loc) {
    State->Str->MCStreamer::EmitWinCFIStartProc(unwrap(Symbol), unwrap(Loc));
    checkError();
  }

  virtual void emit_win_cfi_end_proc(std::shared_ptr<ParserState> State,
                                     std::shared_ptr<mc::SourceLocation> Loc) {
    State->Str->MCStreamer::EmitWinCFIEndProc(unwrap(Loc));
    checkError();
  }

  virtual void
  emit_win_cfi_funclet_or_func_end(std::shared_ptr<ParserState> State,
                                   std::shared_ptr<mc::SourceLocation> Loc) {
    State->Str->MCStreamer::EmitWinCFIFuncletOrFuncEnd(unwrap(Loc));
    checkError();
  }

  virtual void
  emit_win_cfi_start_chained(std::shared_ptr<ParserState> State,
                             std::shared_ptr<mc::SourceLocation> Loc) {
    State->Str->MCStreamer::EmitWinCFIStartChained(unwrap(Loc));
    checkError();
  }

  virtual void
  emit_win_cfi_end_chained(std::shared_ptr<ParserState> State,
                           std::shared_ptr<mc::SourceLocation> Loc) {
    State->Str->MCStreamer::EmitWinCFIEndChained(unwrap(Loc));
    checkError();
  }

  virtual void emit_win_cfi_push_reg(std::shared_ptr<ParserState> State,
                                     std::shared_ptr<mc::Register> Register,
                                     std::shared_ptr<mc::SourceLocation> Loc) {
    State->Str->MCStreamer::EmitWinCFIPushReg(unwrap(Register), unwrap(Loc));
    checkError();
  }

  virtual void emit_win_cfi_set_frame(std::shared_ptr<ParserState> State,
                                      std::shared_ptr<mc::Register> Register,
                                      unsigned Offset,
                                      std::shared_ptr<mc::SourceLocation> Loc) {
    State->Str->MCStreamer::EmitWinCFISetFrame(unwrap(Register), Offset,
                                               unwrap(Loc));
    checkError();
  }

  virtual void
  emit_win_cfi_alloc_stack(std::shared_ptr<ParserState> State, unsigned Size,
                           std::shared_ptr<mc::SourceLocation> Loc) {
    State->Str->MCStreamer::EmitWinCFIAllocStack(Size, unwrap(Loc));
    checkError();
  }

  virtual void emit_win_cfi_save_reg(std::shared_ptr<ParserState> State,
                                     std::shared_ptr<mc::Register> Register,
                                     unsigned Offset,
                                     std::shared_ptr<mc::SourceLocation> Loc) {
    State->Str->MCStreamer::EmitWinCFISaveReg(unwrap(Register), Offset,
                                              unwrap(Loc));
    checkError();
  }

  virtual void emit_win_cfi_save_xmm(std::shared_ptr<ParserState> State,
                                     std::shared_ptr<mc::Register> Register,
                                     unsigned Offset,
                                     std::shared_ptr<mc::SourceLocation> Loc) {
    State->Str->MCStreamer::EmitWinCFISaveXMM(unwrap(Register), Offset,
                                              unwrap(Loc));
    checkError();
  }

  virtual void
  emit_win_cfi_push_frame(std::shared_ptr<ParserState> State, bool Code,
                          std::shared_ptr<mc::SourceLocation> Loc) {
    State->Str->MCStreamer::EmitWinCFIPushFrame(Code, unwrap(Loc));
    checkError();
  }

  virtual void
  emit_win_cfi_end_prolog(std::shared_ptr<ParserState> State,
                          std::shared_ptr<mc::SourceLocation> Loc) {
    State->Str->MCStreamer::EmitWinCFIEndProlog(unwrap(Loc));
    checkError();
  }

  virtual void emit_win_eh_handler(std::shared_ptr<ParserState> State,
                                   std::shared_ptr<mc::Symbol> Sym, bool Unwind,
                                   bool Except,
                                   std::shared_ptr<mc::SourceLocation> Loc) {
    State->Str->MCStreamer::EmitWinEHHandler(unwrap(Sym), Unwind, Except,
                                             unwrap(Loc));
    checkError();
  }

  virtual void
  emit_win_eh_handler_data(std::shared_ptr<ParserState> State,
                           std::shared_ptr<mc::SourceLocation> Loc) {
    State->Str->MCStreamer::EmitWinEHHandlerData(unwrap(Loc));
    checkError();
  }

  virtual void emit_cg_profile_entry(std::shared_ptr<ParserState> State,
                                     std::shared_ptr<mc::SymbolRefExpr> From,
                                     std::shared_ptr<mc::SymbolRefExpr> To,
                                     uint64_t Count) {
    State->Str->MCStreamer::emitCGProfileEntry(unwrap(From), unwrap(To), Count);
    checkError();
  }

  virtual void emit_syntax_directive(std::shared_ptr<ParserState> State) {
    State->Str->MCStreamer::emitSyntaxDirective();
    checkError();
  }

#if NOT_IMPLEMENTED
  virtual Optional<std::pair<bool, std::string>>
  emit_reloc_directive(std::shared_ptr<ParserState> State,
                       std::shared_ptr<mc::Expr> Offset, std::string_view Name,
                       std::shared_ptr<mc::Expr> Expr,
                       std::shared_ptr<mc::SourceLocation> Loc,
                       std::shared_ptr<mc::SubtargetInfo> STI) {
    auto Result = State->Str->MCStreamer::emitRelocDirective(
        unwrap(Offset), Name, unwrap(Expr), unwrap(Loc), unwrap(STI));
    checkError();
    return Result;
  }
#endif

  virtual void emit_addrsig(std::shared_ptr<ParserState> State) {
    State->Str->MCStreamer::emitAddrsig();
    checkError();
  }

  virtual void emit_addrsig_sym(std::shared_ptr<ParserState> State,
                                std::shared_ptr<mc::Symbol> Sym) {
    State->Str->MCStreamer::emitAddrsigSym(unwrap(Sym));
    checkError();
  }

#if NOT_IMPLEMENTED
  virtual void
  emit_pseudo_probe(std::shared_ptr<ParserState> State, uint64_t Guid,
                    uint64_t Index, uint64_t Type, uint64_t Attr,
                    std::shared_ptr<mc::PseudoProbeInlineStack> InlineStack) {
    State->Str->MCStreamer::emitPseudoProbe(Guid, Index, Type, Attr,
                                            unwrap(InlineStack));
    checkError();
  }
#endif

  virtual void emit_bundle_align_mode(std::shared_ptr<ParserState> State,
                                      unsigned AlignPow2) {
    State->Str->MCStreamer::emitBundleAlignMode(AlignPow2);
    checkError();
  }

  virtual void emit_bundle_lock(std::shared_ptr<ParserState> State,
                                bool AlignToEnd) {
    State->Str->MCStreamer::emitBundleLock(AlignToEnd);
    checkError();
  }

  virtual void emit_bundle_unlock(std::shared_ptr<ParserState> State) {
    State->Str->MCStreamer::emitBundleUnlock();
    checkError();
  }

#if NOT_IMPLEMENTED
  virtual void emit_dwarf_unit_length(std::shared_ptr<ParserState> State, uint64_t Length, ? Comment) {
    State->Str->MCStreamer::emitDwarfUnitLength(Length, ?);
    checkError();
  }

  virtual void emit_dwarf_unit_length(std::shared_ptr<ParserState> State, ? Prefix, ? Comment) {
    return State->Str->MCStreamer::emitDwarfUnitLength(?, ?);
    checkError();
  }
#endif

  virtual void
  emit_dwarf_line_start_label(std::shared_ptr<ParserState> State,
                              std::shared_ptr<mc::Symbol> StartSym) {
    State->Str->MCStreamer::emitDwarfLineStartLabel(unwrap(StartSym));
    checkError();
  }

  virtual void
  emit_dwarf_line_end_entry(std::shared_ptr<ParserState> State,
                            std::shared_ptr<mc::Section> Section,
                            std::shared_ptr<mc::Symbol> LastLabel) {
    State->Str->MCStreamer::emitDwarfLineEndEntry(unwrap(Section),
                                                  unwrap(LastLabel));
    checkError();
  }

  virtual void emit_dwarf_advance_line_addr(
      std::shared_ptr<ParserState> State, int64_t LineDelta,
      std::shared_ptr<mc::Symbol> LastLabel, std::shared_ptr<mc::Symbol> Label,
      unsigned PointerSize) {
    State->Str->MCStreamer::emitDwarfAdvanceLineAddr(
        LineDelta, unwrap(LastLabel), unwrap(Label), PointerSize);
    checkError();
  }

  virtual void
  emit_instruction(std::shared_ptr<ParserState> State,
                   std::shared_ptr<mc::Instruction> Inst, py::bytes Bytes,
                   std::vector<std::shared_ptr<mc::Fixup>>& Fixups) {
    State->Str->MCStreamer::emitInstruction(unwrap(Inst), *State->STI);
    checkError();
  }

  virtual void diagnostic(std::shared_ptr<ParserState> State,
                          std::shared_ptr<mc::Diagnostic> Diag) {}

private:
  void checkError() {
    // This needs to be invoked after every call to the MCStreamer base class
    // because it's possible it called additional Python code that set an
    // error.
    if (PyErr_Occurred())
      throw py::error_already_set();
  }
};

class PyStreamer : public StreamerBase {
public:
  void
  emit_cfi_start_proc_impl(std::shared_ptr<ParserState> State,
                           std::shared_ptr<mc::DwarfFrameInfo> Frame) override {
    PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_start_proc_impl, State,
                      Frame);
  }

  void emit_cfi_end_proc_impl(
      std::shared_ptr<ParserState> State,
      std::shared_ptr<mc::DwarfFrameInfo> CurFrame) override {
    PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_end_proc_impl, State,
                      CurFrame);
  }

#if NOT_IMPLEMENTED
void emit_windows_unwind_tables(std::shared_ptr<ParserState> State, ? Frame) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_windows_unwind_tables, State,
                    Frame);
}
#endif

void emit_windows_unwind_tables(std::shared_ptr<ParserState> State) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_windows_unwind_tables, State);
}

void emit_raw_text_impl(std::shared_ptr<ParserState> State,
                        std::string_view String) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_raw_text_impl, State, String);
}

#if NOT_IMPLEMENTED
void emit_cfi_label(std::shared_ptr<ParserState> State) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_label, State);
}
#endif

void add_comment(std::shared_ptr<ParserState> State, std::string_view T,
                 bool EOL) override {
  PYBIND11_OVERRIDE(void, StreamerBase, add_comment, State, T, EOL);
}

void emit_raw_comment(std::shared_ptr<ParserState> State, std::string_view T,
                      bool TabPrefix) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_raw_comment, State, T, TabPrefix);
}

void add_explicit_comment(std::shared_ptr<ParserState> State,
                          std::string_view T) override {
  PYBIND11_OVERRIDE(void, StreamerBase, add_explicit_comment, State, T);
}

void emit_explicit_comments(std::shared_ptr<ParserState> State) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_explicit_comments, State);
}

void change_section(std::shared_ptr<ParserState> State,
                    std::shared_ptr<mc::Section> Section,
                    std::shared_ptr<mc::Expr> SubSection) override {
  PYBIND11_OVERRIDE(void, StreamerBase, change_section, State, Section,
                    SubSection);
}

void init_sections(std::shared_ptr<ParserState> State,
                   bool NoExecStack) override {
  PYBIND11_OVERRIDE(void, StreamerBase, init_sections, State, NoExecStack);
}

void emit_label(std::shared_ptr<ParserState> State,
                std::shared_ptr<mc::Symbol> Symbol,
                std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_label, State, Symbol, Loc);
}

void emit_eh_sym_attributes(std::shared_ptr<ParserState> State,
                            std::shared_ptr<mc::Symbol> Symbol,
                            std::shared_ptr<mc::Symbol> EHSymbol) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_eh_sym_attributes, State, Symbol,
                    EHSymbol);
}

void emit_assembler_flag(std::shared_ptr<ParserState> State,
                         MCAssemblerFlag Flag) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_assembler_flag, State, Flag);
}

void emit_linker_options(std::shared_ptr<ParserState> State,
                         std::vector<std::string>& Kind) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_linker_options, State, Kind);
}

void emit_data_region(std::shared_ptr<ParserState> State,
                      MCDataRegionType Kind) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_data_region, State, Kind);
}

#if NOT_IMPLEMENTED
void emit_version_min(std::shared_ptr<ParserState> State, MCVersionMinType Type, unsigned Major, unsigned Minor, unsigned Update, ? SDKVersion) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_version_min, State, Type, Major,
                    Minor, Update, SDKVersion);
}

void emit_build_version(std::shared_ptr<ParserState> State, unsigned Platform, unsigned Major, unsigned Minor, unsigned Update, ? SDKVersion) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_build_version, State, Platform,
                    Major, Minor, Update, SDKVersion);
}
#endif

void emit_thumb_func(std::shared_ptr<ParserState> State,
                     std::shared_ptr<mc::Symbol> Func) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_thumb_func, State, Func);
}

void emit_assignment(std::shared_ptr<ParserState> State,
                     std::shared_ptr<mc::Symbol> Symbol,
                     std::shared_ptr<mc::Expr> Value) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_assignment, State, Symbol, Value);
}

void emit_weak_reference(std::shared_ptr<ParserState> State,
                         std::shared_ptr<mc::Symbol> Alias,
                         std::shared_ptr<mc::Symbol> Symbol) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_weak_reference, State, Alias,
                    Symbol);
}

bool emit_symbol_attribute(std::shared_ptr<ParserState> State,
                           std::shared_ptr<mc::Symbol> Symbol,
                           MCSymbolAttr Attribute) override {
  PYBIND11_OVERRIDE(bool, StreamerBase, emit_symbol_attribute, State, Symbol,
                    Attribute);
  return false;
}

void emit_symbol_desc(std::shared_ptr<ParserState> State,
                      std::shared_ptr<mc::Symbol> Symbol,
                      unsigned DescValue) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_symbol_desc, State, Symbol,
                    DescValue);
}

void begin_coff_symbol_def(std::shared_ptr<ParserState> State,
                           std::shared_ptr<mc::Symbol> Symbol) override {
  PYBIND11_OVERRIDE(void, StreamerBase, begin_coff_symbol_def, State, Symbol);
}

void emit_coff_symbol_storage_class(std::shared_ptr<ParserState> State,
                                    int StorageClass) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_coff_symbol_storage_class, State,
                    StorageClass);
}

void emit_coff_symbol_type(std::shared_ptr<ParserState> State,
                           int Type) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_coff_symbol_type, State, Type);
}

void end_coff_symbol_def(std::shared_ptr<ParserState> State) override {
  PYBIND11_OVERRIDE(void, StreamerBase, end_coff_symbol_def, State);
}

void emit_coff_safe_seh(std::shared_ptr<ParserState> State,
                        std::shared_ptr<mc::Symbol> Symbol) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_coff_safe_seh, State, Symbol);
}

void emit_coff_symbol_index(std::shared_ptr<ParserState> State,
                            std::shared_ptr<mc::Symbol> Symbol) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_coff_symbol_index, State, Symbol);
}

void emit_coff_section_index(std::shared_ptr<ParserState> State,
                             std::shared_ptr<mc::Symbol> Symbol) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_coff_section_index, State, Symbol);
}

void emit_coff_secprel32(std::shared_ptr<ParserState> State,
                         std::shared_ptr<mc::Symbol> Symbol,
                         uint64_t Offset) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_coff_secprel32, State, Symbol,
                    Offset);
}

void emit_coff_imgprel32(std::shared_ptr<ParserState> State,
                         std::shared_ptr<mc::Symbol> Symbol,
                         int64_t Offset) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_coff_imgprel32, State, Symbol,
                    Offset);
}

void emit_xcoff_local_common_symbol(std::shared_ptr<ParserState> State,
                                    std::shared_ptr<mc::Symbol> LabelSym,
                                    uint64_t Size,
                                    std::shared_ptr<mc::Symbol> CsectSym,
                                    unsigned ByteAlignment) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_xcoff_local_common_symbol, State,
                    LabelSym, Size, CsectSym, ByteAlignment);
}

void emit_xcoff_symbol_linkage_with_visibility(
    std::shared_ptr<ParserState> State, std::shared_ptr<mc::Symbol> Symbol,
    MCSymbolAttr Linkage, MCSymbolAttr Visibility) override {
  PYBIND11_OVERRIDE(void, StreamerBase,
                    emit_xcoff_symbol_linkage_with_visibility, State, Symbol,
                    Linkage, Visibility);
}

void emit_xcoff_rename_directive(std::shared_ptr<ParserState> State,
                                 std::shared_ptr<mc::Symbol> Name,
                                 std::string_view Rename) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_xcoff_rename_directive, State,
                    Name, Rename);
}

void emit_elf_size(std::shared_ptr<ParserState> State,
                   std::shared_ptr<mc::Symbol> Symbol,
                   std::shared_ptr<mc::Expr> Value) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_elf_size, State, Symbol, Value);
}

void emit_elf_symver_directive(std::shared_ptr<ParserState> State,
                               std::shared_ptr<mc::Symbol> OriginalSym,
                               std::string_view Name,
                               bool KeepOriginalSym) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_elf_symver_directive, State,
                    OriginalSym, Name, KeepOriginalSym);
}

#if NOT_IMPLEMENTED
void emit_loh_directive(std::shared_ptr<ParserState> State, MCLOHType Kind,
                        std::shared_ptr<mc::LOHArgs> Args) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_loh_directive, State, Kind, Args);
}
#endif

void emit_gnu_attribute(std::shared_ptr<ParserState> State, unsigned Tag,
                        unsigned Value) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_gnu_attribute, State, Tag, Value);
}

void emit_common_symbol(std::shared_ptr<ParserState> State,
                        std::shared_ptr<mc::Symbol> Symbol, uint64_t Size,
                        unsigned ByteAlignment) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_common_symbol, State, Symbol, Size,
                    ByteAlignment);
}

void emit_local_common_symbol(std::shared_ptr<ParserState> State,
                              std::shared_ptr<mc::Symbol> Symbol, uint64_t Size,
                              unsigned ByteAlignment) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_local_common_symbol, State, Symbol,
                    Size, ByteAlignment);
}

void emit_zero_fill(std::shared_ptr<ParserState> State,
                    std::shared_ptr<mc::Section> Section,
                    std::shared_ptr<mc::Symbol> Symbol, uint64_t Size,
                    unsigned ByteAlignment,
                    std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_zero_fill, State, Section, Symbol,
                    Size, ByteAlignment, Loc);
}

void emit_tbss_symbol(std::shared_ptr<ParserState> State,
                      std::shared_ptr<mc::Section> Section,
                      std::shared_ptr<mc::Symbol> Symbol, uint64_t Size,
                      unsigned ByteAlignment) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_tbss_symbol, State, Section,
                    Symbol, Size, ByteAlignment);
}

void emit_bytes(std::shared_ptr<ParserState> State, py::bytes Data) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_bytes, State, Data);
}

void emit_binary_data(std::shared_ptr<ParserState> State,
                      py::bytes Data) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_binary_data, State, Data);
}

void emit_value_impl(std::shared_ptr<ParserState> State,
                     std::shared_ptr<mc::Expr> Value, unsigned Size,
                     std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_value_impl, State, Value, Size,
                    Loc);
}

void emit_int_value(std::shared_ptr<ParserState> State, uint64_t Value,
                    unsigned Size) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_int_value, State, Value, Size);
}

#if NOT_IMPLEMENTED
void emit_int_value(std::shared_ptr<ParserState> State, ? Value) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_int_value, State, Value);
}
#endif

void emit_int_value_in_hex(std::shared_ptr<ParserState> State, uint64_t Value,
                           unsigned Size) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_int_value_in_hex, State, Value,
                    Size);
}

void emit_int_value_in_hex_with_padding(std::shared_ptr<ParserState> State,
                                        uint64_t Value,
                                        unsigned Size) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_int_value_in_hex_with_padding,
                    State, Value, Size);
}

void emit_uleb128_value(std::shared_ptr<ParserState> State,
                        std::shared_ptr<mc::Expr> Value) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_uleb128_value, State, Value);
}

void emit_sleb128_value(std::shared_ptr<ParserState> State,
                        std::shared_ptr<mc::Expr> Value) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_sleb128_value, State, Value);
}

void emit_dtprel64_value(std::shared_ptr<ParserState> State,
                         std::shared_ptr<mc::Expr> Value) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_dtprel64_value, State, Value);
}

void emit_dtprel32_value(std::shared_ptr<ParserState> State,
                         std::shared_ptr<mc::Expr> Value) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_dtprel32_value, State, Value);
}

void emit_tprel64_value(std::shared_ptr<ParserState> State,
                        std::shared_ptr<mc::Expr> Value) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_tprel64_value, State, Value);
}

void emit_tprel32_value(std::shared_ptr<ParserState> State,
                        std::shared_ptr<mc::Expr> Value) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_tprel32_value, State, Value);
}

void emit_gprel64_value(std::shared_ptr<ParserState> State,
                        std::shared_ptr<mc::Expr> Value) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_gprel64_value, State, Value);
}

void emit_gprel32_value(std::shared_ptr<ParserState> State,
                        std::shared_ptr<mc::Expr> Value) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_gprel32_value, State, Value);
}

void emit_value_fill(std::shared_ptr<ParserState> State,
                     std::shared_ptr<mc::Expr> NumBytes, uint64_t FillValue,
                     std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_value_fill, State, NumBytes,
                    FillValue, Loc);
}

void emit_expr_fill(std::shared_ptr<ParserState> State,
                    std::shared_ptr<mc::Expr> NumValues, int64_t Size,
                    int64_t Expr,
                    std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_expr_fill, State, NumValues, Size,
                    Expr, Loc);
}

void emit_nops(std::shared_ptr<ParserState> State, int64_t NumBytes,
               int64_t ControlledNopLength,
               std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_nops, State, NumBytes,
                    ControlledNopLength, Loc);
}

void emit_value_to_alignment(std::shared_ptr<ParserState> State,
                             unsigned ByteAlignment, int64_t Value,
                             unsigned ValueSize,
                             unsigned MaxBytesToEmit) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_value_to_alignment, State,
                    ByteAlignment, Value, ValueSize, MaxBytesToEmit);
}

void emit_code_alignment(std::shared_ptr<ParserState> State,
                         unsigned ByteAlignment,
                         unsigned MaxBytesToEmit) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_code_alignment, State,
                    ByteAlignment, MaxBytesToEmit);
}

void emit_value_to_offset(std::shared_ptr<ParserState> State,
                          std::shared_ptr<mc::Expr> Offset, unsigned char Value,
                          std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_value_to_offset, State, Offset,
                    Value, Loc);
}

void emit_file_directive(std::shared_ptr<ParserState> State,
                         std::string_view Filename) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_file_directive, State, Filename);
}

void emit_file_directive(std::shared_ptr<ParserState> State,
                         std::string_view Filename,
                         std::string_view CompilerVerion,
                         std::string_view TimeStamp,
                         std::string_view Description) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_file_directive, State, Filename,
                    CompilerVerion, TimeStamp, Description);
}

void emit_ident(std::shared_ptr<ParserState> State,
                std::string_view IdentString) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_ident, State, IdentString);
}

#if NOT_IMPLEMENTED
void try_emit_dwarf_file_directive(std::shared_ptr<ParserState> State, unsigned FileNo, std::string_view Directory, std::string_view Filename, ? Checksum, ? Source, unsigned CUID) override {
  PYBIND11_OVERRIDE(void, StreamerBase, try_emit_dwarf_file_directive, State,
                    FileNo, Directory, Filename, Checksum, Source, CUID);
}

void emit_dwarf_file_0_directive(std::shared_ptr<ParserState> State, std::string_view Directory, std::string_view Filename, ? Checksum, ? Source, unsigned CUID) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_dwarf_file_0_directive, State,
                    Directory, Filename, Checksum, Source, CUID);
}
#endif

void emit_cfi_b_key_frame(std::shared_ptr<ParserState> State) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_b_key_frame, State);
}

void emit_dwarf_loc_directive(std::shared_ptr<ParserState> State,
                              unsigned FileNo, unsigned Line, unsigned Column,
                              unsigned Flags, unsigned Isa,
                              unsigned Discriminator,
                              std::string_view FileName) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_dwarf_loc_directive, State, FileNo,
                    Line, Column, Flags, Isa, Discriminator, FileName);
}

#if NOT_IMPLEMENTED
void emit_cv_file_directive(std::shared_ptr<ParserState> State, unsigned FileNo, std::string_view Filename, ? Checksum, unsigned ChecksumKind) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cv_file_directive, State, FileNo,
                    Filename, Checksum, ChecksumKind);
}

void emit_cv_func_id_directive(std::shared_ptr<ParserState> State,
                               unsigned FunctionId) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cv_func_id_directive, State,
                    FunctionId);
}

void emit_cv_inline_site_id_directive(
    std::shared_ptr<ParserState> State, unsigned FunctionId, unsigned IAFunc,
    unsigned IAFile, unsigned IALine, unsigned IACol,
    std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cv_inline_site_id_directive, State,
                    FunctionId, IAFunc, IAFile, IALine, IACol, Loc);
}
#endif

void emit_cv_loc_directive(std::shared_ptr<ParserState> State,
                           unsigned FunctionId, unsigned FileNo, unsigned Line,
                           unsigned Column, bool PrologueEnd, bool IsStmt,
                           std::string_view FileName,
                           std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cv_loc_directive, State,
                    FunctionId, FileNo, Line, Column, PrologueEnd, IsStmt,
                    FileName, Loc);
}

void emit_cv_line_table_directive(std::shared_ptr<ParserState> State,
                                  unsigned FunctionId,
                                  std::shared_ptr<mc::Symbol> FnStart,
                                  std::shared_ptr<mc::Symbol> FnEnd) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cv_line_table_directive, State,
                    FunctionId, FnStart, FnEnd);
}

void emit_cv_inline_line_table_directive(
    std::shared_ptr<ParserState> State, unsigned PrimaryFunctionId,
    unsigned SourceFileId, unsigned SourceLineNum,
    std::shared_ptr<mc::Symbol> FnStartSym,
    std::shared_ptr<mc::Symbol> FnEndSym) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cv_inline_line_table_directive,
                    State, PrimaryFunctionId, SourceFileId, SourceLineNum,
                    FnStartSym, FnEndSym);
}

#if NOT_IMPLEMENTED
void emit_cv_def_range_directive(std::shared_ptr<ParserState> State, ? Ranges, std::string_view FixedSizePortion) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cv_def_range_directive, State,
                    Ranges, FixedSizePortion);
}

void emit_cv_def_range_directive(std::shared_ptr<ParserState> State, ? Ranges, ? DRHdr) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cv_def_range_directive, State,
                    Ranges, DRHdr);
}

void emit_cv_def_range_directive(std::shared_ptr<ParserState> State, ? Ranges, ? DRHdr) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cv_def_range_directive, State,
                    Ranges, DRHdr);
}

void emit_cv_def_range_directive(std::shared_ptr<ParserState> State, ? Ranges, ? DRHdr) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cv_def_range_directive, State,
                    Ranges, DRHdr);
}

void emit_cv_def_range_directive(std::shared_ptr<ParserState> State, ? Ranges, ? DRHdr) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cv_def_range_directive, State,
                    Ranges, DRHdr);
}
#endif

void emit_cv_string_table_directive(
    std::shared_ptr<ParserState> State) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cv_string_table_directive, State);
}

void emit_cv_file_checksums_directive(
    std::shared_ptr<ParserState> State) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cv_file_checksums_directive,
                    State);
}

void emit_cv_file_checksum_offset_directive(std::shared_ptr<ParserState> State,
                                            unsigned FileNo) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cv_file_checksum_offset_directive,
                    State, FileNo);
}

void emit_cv_fpo_data(std::shared_ptr<ParserState> State,
                      std::shared_ptr<mc::Symbol> ProcSym,
                      std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cv_fpo_data, State, ProcSym, Loc);
}

void emit_absolute_symbol_diff(std::shared_ptr<ParserState> State,
                               std::shared_ptr<mc::Symbol> Hi,
                               std::shared_ptr<mc::Symbol> Lo,
                               unsigned Size) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_absolute_symbol_diff, State, Hi,
                    Lo, Size);
}

void emit_absolute_symbol_diff_as_uleb128(
    std::shared_ptr<ParserState> State, std::shared_ptr<mc::Symbol> Hi,
    std::shared_ptr<mc::Symbol> Lo) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_absolute_symbol_diff_as_uleb128,
                    State, Hi, Lo);
}

std::shared_ptr<mc::Symbol>
get_dwarf_line_table_symbol(std::shared_ptr<ParserState> State,
                            unsigned CUID) override {
  PYBIND11_OVERRIDE(std::shared_ptr<mc::Symbol>, StreamerBase,
                    get_dwarf_line_table_symbol, State, CUID);
  return nullptr;
}

void emit_cfi_sections(std::shared_ptr<ParserState> State, bool EH,
                       bool Debug) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_sections, State, EH, Debug);
}

void emit_cfi_def_cfa(std::shared_ptr<ParserState> State, int64_t Register,
                      int64_t Offset) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_def_cfa, State, Register,
                    Offset);
}

void emit_cfi_def_cfa_offset(std::shared_ptr<ParserState> State,
                             int64_t Offset) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_def_cfa_offset, State, Offset);
}

void emit_cfi_def_cfa_register(std::shared_ptr<ParserState> State,
                               int64_t Register) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_def_cfa_register, State,
                    Register);
}

void emit_cfi_llvm_def_aspace_cfa(std::shared_ptr<ParserState> State,
                                  int64_t Register, int64_t Offset,
                                  int64_t AddressSpace) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_llvm_def_aspace_cfa, State,
                    Register, Offset, AddressSpace);
}

void emit_cfi_offset(std::shared_ptr<ParserState> State, int64_t Register,
                     int64_t Offset) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_offset, State, Register,
                    Offset);
}

void emit_cfi_personality(std::shared_ptr<ParserState> State,
                          std::shared_ptr<mc::Symbol> Sym,
                          unsigned Encoding) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_personality, State, Sym,
                    Encoding);
}

void emit_cfi_lsda(std::shared_ptr<ParserState> State,
                   std::shared_ptr<mc::Symbol> Sym,
                   unsigned Encoding) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_lsda, State, Sym, Encoding);
}

void emit_cfi_remember_state(std::shared_ptr<ParserState> State) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_remember_state, State);
}

void emit_cfi_restore_state(std::shared_ptr<ParserState> State) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_restore_state, State);
}

void emit_cfi_same_value(std::shared_ptr<ParserState> State,
                         int64_t Register) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_same_value, State, Register);
}

void emit_cfi_restore(std::shared_ptr<ParserState> State,
                      int64_t Register) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_restore, State, Register);
}

void emit_cfi_rel_offset(std::shared_ptr<ParserState> State, int64_t Register,
                         int64_t Offset) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_rel_offset, State, Register,
                    Offset);
}

void emit_cfi_adjust_cfa_offset(std::shared_ptr<ParserState> State,
                                int64_t Adjustment) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_adjust_cfa_offset, State,
                    Adjustment);
}

void emit_cfi_escape(std::shared_ptr<ParserState> State,
                     std::string_view Values) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_escape, State, Values);
}

void emit_cfi_return_column(std::shared_ptr<ParserState> State,
                            int64_t Register) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_return_column, State,
                    Register);
}

void emit_cfi_gnu_args_size(std::shared_ptr<ParserState> State,
                            int64_t Size) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_gnu_args_size, State, Size);
}

void emit_cfi_signal_frame(std::shared_ptr<ParserState> State) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_signal_frame, State);
}

void emit_cfi_undefined(std::shared_ptr<ParserState> State,
                        int64_t Register) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_undefined, State, Register);
}

void emit_cfi_register(std::shared_ptr<ParserState> State, int64_t Register1,
                       int64_t Register2) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_register, State, Register1,
                    Register2);
}

void emit_cfi_window_save(std::shared_ptr<ParserState> State) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_window_save, State);
}

void emit_cfi_negate_ra_state(std::shared_ptr<ParserState> State) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cfi_negate_ra_state, State);
}

void emit_win_cfi_start_proc(std::shared_ptr<ParserState> State,
                             std::shared_ptr<mc::Symbol> Symbol,
                             std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_win_cfi_start_proc, State, Symbol,
                    Loc);
}

void emit_win_cfi_end_proc(std::shared_ptr<ParserState> State,
                           std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_win_cfi_end_proc, State, Loc);
}

void emit_win_cfi_funclet_or_func_end(
    std::shared_ptr<ParserState> State,
    std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_win_cfi_funclet_or_func_end, State,
                    Loc);
}

void emit_win_cfi_start_chained(
    std::shared_ptr<ParserState> State,
    std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_win_cfi_start_chained, State, Loc);
}

void emit_win_cfi_end_chained(
    std::shared_ptr<ParserState> State,
    std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_win_cfi_end_chained, State, Loc);
}

void emit_win_cfi_push_reg(std::shared_ptr<ParserState> State,
                           std::shared_ptr<mc::Register> Register,
                           std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_win_cfi_push_reg, State, Register,
                    Loc);
}

void emit_win_cfi_set_frame(std::shared_ptr<ParserState> State,
                            std::shared_ptr<mc::Register> Register,
                            unsigned Offset,
                            std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_win_cfi_set_frame, State, Register,
                    Offset, Loc);
}

void emit_win_cfi_alloc_stack(
    std::shared_ptr<ParserState> State, unsigned Size,
    std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_win_cfi_alloc_stack, State, Size,
                    Loc);
}

void emit_win_cfi_save_reg(std::shared_ptr<ParserState> State,
                           std::shared_ptr<mc::Register> Register,
                           unsigned Offset,
                           std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_win_cfi_save_reg, State, Register,
                    Offset, Loc);
}

void emit_win_cfi_save_xmm(std::shared_ptr<ParserState> State,
                           std::shared_ptr<mc::Register> Register,
                           unsigned Offset,
                           std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_win_cfi_save_xmm, State, Register,
                    Offset, Loc);
}

void emit_win_cfi_push_frame(std::shared_ptr<ParserState> State, bool Code,
                             std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_win_cfi_push_frame, State, Code,
                    Loc);
}

void emit_win_cfi_end_prolog(std::shared_ptr<ParserState> State,
                             std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_win_cfi_end_prolog, State, Loc);
}

void emit_win_eh_handler(std::shared_ptr<ParserState> State,
                         std::shared_ptr<mc::Symbol> Sym, bool Unwind,
                         bool Except,
                         std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_win_eh_handler, State, Sym, Unwind,
                    Except, Loc);
}

void emit_win_eh_handler_data(
    std::shared_ptr<ParserState> State,
    std::shared_ptr<mc::SourceLocation> Loc) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_win_eh_handler_data, State, Loc);
}

void emit_cg_profile_entry(std::shared_ptr<ParserState> State,
                           std::shared_ptr<mc::SymbolRefExpr> From,
                           std::shared_ptr<mc::SymbolRefExpr> To,
                           uint64_t Count) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_cg_profile_entry, State, From, To,
                    Count);
}

void emit_syntax_directive(std::shared_ptr<ParserState> State) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_syntax_directive, State);
}

#if NOT_IMPLEMENTED
Optional<std::pair<bool, std::string>>
emit_reloc_directive(std::shared_ptr<ParserState> State,
                     std::shared_ptr<mc::Expr> Offset, std::string_view Name,
                     std::shared_ptr<mc::Expr> Expr,
                     std::shared_ptr<mc::SourceLocation> Loc,
                     std::shared_ptr<mc::SubtargetInfo> STI) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_reloc_directive, State, Offset,
                    Name, Expr, Loc, STI);
}
#endif

void emit_addrsig(std::shared_ptr<ParserState> State) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_addrsig, State);
}

void emit_addrsig_sym(std::shared_ptr<ParserState> State,
                      std::shared_ptr<mc::Symbol> Sym) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_addrsig_sym, State, Sym);
}

#if NOT_IMPLEMENTED
void emit_pseudo_probe(
    std::shared_ptr<ParserState> State, uint64_t Guid, uint64_t Index,
    uint64_t Type, uint64_t Attr,
    std::shared_ptr<mc::PseudoProbeInlineStack> InlineStack) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_pseudo_probe, State, Guid, Index,
                    Type, Attr, InlineStack);
}
#endif

void emit_bundle_align_mode(std::shared_ptr<ParserState> State,
                            unsigned AlignPow2) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_bundle_align_mode, State,
                    AlignPow2);
}

void emit_bundle_lock(std::shared_ptr<ParserState> State,
                      bool AlignToEnd) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_bundle_lock, State, AlignToEnd);
}

void emit_bundle_unlock(std::shared_ptr<ParserState> State) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_bundle_unlock, State);
}

#if NOT_IMPLEMENTED
void emit_dwarf_unit_length(std::shared_ptr<ParserState> State, uint64_t Length, ? Comment) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_dwarf_unit_length, State, Length,
                    Comment);
}

void emit_dwarf_unit_length(std::shared_ptr<ParserState> State, ? Prefix, ? Comment) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_dwarf_unit_length, State, Prefix,
                    Comment);
}
#endif

void emit_dwarf_line_start_label(
    std::shared_ptr<ParserState> State,
    std::shared_ptr<mc::Symbol> StartSym) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_dwarf_line_start_label, State,
                    StartSym);
}

void emit_dwarf_line_end_entry(std::shared_ptr<ParserState> State,
                               std::shared_ptr<mc::Section> Section,
                               std::shared_ptr<mc::Symbol> LastLabel) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_dwarf_line_end_entry, State,
                    Section, LastLabel);
}

void emit_dwarf_advance_line_addr(std::shared_ptr<ParserState> State,
                                  int64_t LineDelta,
                                  std::shared_ptr<mc::Symbol> LastLabel,
                                  std::shared_ptr<mc::Symbol> Label,
                                  unsigned PointerSize) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_dwarf_advance_line_addr, State,
                    LineDelta, LastLabel, Label, PointerSize);
}

void emit_instruction(
    std::shared_ptr<ParserState> State, std::shared_ptr<mc::Instruction> Inst,
    py::bytes Bytes, std::vector<std::shared_ptr<mc::Fixup>>& Fixups) override {
  PYBIND11_OVERRIDE(void, StreamerBase, emit_instruction, State, Inst, Bytes,
                    Fixups);
}

void diagnostic(std::shared_ptr<ParserState> State,
                std::shared_ptr<mc::Diagnostic> Diag) override {
  PYBIND11_OVERRIDE(void, StreamerBase, diagnostic, State, Diag);
}
};

#undef DISPATCH

class StreamerAdaptor : public FriendlyStreamer {
  std::weak_ptr<ParserState> WeakState;
  StreamerBase& Streamer;

public:
  StreamerAdaptor(std::shared_ptr<ParserState> State, StreamerBase& Streamer)
      : FriendlyStreamer(*State->Ctx), WeakState(State), Streamer(Streamer) {}

  /**
   * Invokes a StreamerBase member function with the given arguments, taking
   * care to handle Python exceptions.
   */
  template <typename Fn, typename... Args,
            typename RetT = std::invoke_result_t<
                Fn, decltype(Streamer), decltype(WeakState.lock()), Args...>>
  RetT dispatch(Fn&& fn, Args&&... args) {
    if (auto State = WeakState.lock()) {
      // We can't immediately unwind to Python code if our callbacks raise
      // an exception because LLVM is not exception-safe. What we'll do
      // instead is keep the Python exception set and just not call into
      // Python again.
      if (!PyErr_Occurred()) {
        try {
          return std::invoke(fn, Streamer, State, std::forward<Args>(args)...);
        } catch (py::builtin_exception& e) {
          e.set_error();
        } catch (py::error_already_set& e) {
          e.restore();
        }
      }
    }

    return RetT();
  }

  void emitCFIStartProcImpl(MCDwarfFrameInfo& Frame) override {
    dispatch(&StreamerBase::emit_cfi_start_proc_impl, wrap(&Frame));
  }

  void emitCFIEndProcImpl(MCDwarfFrameInfo& CurFrame) override {
    dispatch(&StreamerBase::emit_cfi_end_proc_impl, wrap(&CurFrame));
  }

#if NOT_IMPLEMENTED
  void EmitWindowsUnwindTables(WinEH::FrameInfo* Frame) override {
  dispatch(&StreamerBase::emit_windows_unwind_tables, ?);
  }
#endif

  void EmitWindowsUnwindTables() override {
    dispatch(&StreamerBase::emit_windows_unwind_tables);
  }

  void emitRawTextImpl(StringRef String) override {
    dispatch(&StreamerBase::emit_raw_text_impl, String);
  }

#if NOT_IMPLEMENTED
  MCSymbol* emitCFILabel() override {
    return unwrap(dispatch(&StreamerBase::emit_cfi_label));
  }
#endif

  void AddComment(const Twine& T, bool EOL = true) override {
    std::string TStr = T.str();
    dispatch(&StreamerBase::add_comment, TStr, EOL);
  }

  void emitRawComment(const Twine& T, bool TabPrefix = true) override {
    std::string TStr = T.str();
    dispatch(&StreamerBase::emit_raw_comment, TStr, TabPrefix);
  }

  void addExplicitComment(const Twine& T) override {
    std::string TStr = T.str();
    dispatch(&StreamerBase::add_explicit_comment, TStr);
  }

  void emitExplicitComments() override {
    dispatch(&StreamerBase::emit_explicit_comments);
  }

  void changeSection(MCSection* Section, const MCExpr* SubSection) override {
    dispatch(&StreamerBase::change_section, wrap(Section), wrap(SubSection));
  }

  void InitSections(bool NoExecStack) override {
    dispatch(&StreamerBase::init_sections, NoExecStack);
  }

  void emitLabel(MCSymbol* Symbol, SMLoc Loc = SMLoc()) override {
    dispatch(&StreamerBase::emit_label, wrap(Symbol), wrap(Loc));
  }

  void emitEHSymAttributes(const MCSymbol* Symbol,
                           MCSymbol* EHSymbol) override {
    dispatch(&StreamerBase::emit_eh_sym_attributes, wrap(Symbol),
             wrap(EHSymbol));
  }

  void emitAssemblerFlag(MCAssemblerFlag Flag) override {
    dispatch(&StreamerBase::emit_assembler_flag, Flag);
  }

  void emitLinkerOptions(ArrayRef<std::string> Kind) override {
    auto KindVec = Kind.vec();
    dispatch(&StreamerBase::emit_linker_options, KindVec);
  }

  void emitDataRegion(MCDataRegionType Kind) override {
    dispatch(&StreamerBase::emit_data_region, Kind);
  }

#if NOT_IMPLEMENTED
  void emitVersionMin(MCVersionMinType Type, unsigned Major, unsigned Minor,
                      unsigned Update, VersionTuple SDKVersion) override {
  dispatch(&StreamerBase::emit_version_min, wrap(Type), Major, Minor, Update, ?);
  }

  void emitBuildVersion(unsigned Platform, unsigned Major, unsigned Minor,
                        unsigned Update, VersionTuple SDKVersion) override {
  dispatch(&StreamerBase::emit_build_version, Platform, Major, Minor, Update, ?);
  }
#endif

  void emitThumbFunc(MCSymbol* Func) override {
    dispatch(&StreamerBase::emit_thumb_func, wrap(Func));
  }

  void emitAssignment(MCSymbol* Symbol, const MCExpr* Value) override {
    dispatch(&StreamerBase::emit_assignment, wrap(Symbol), wrap(Value));
  }

  void emitWeakReference(MCSymbol* Alias, const MCSymbol* Symbol) override {
    dispatch(&StreamerBase::emit_weak_reference, wrap(Alias), wrap(Symbol));
  }

  bool emitSymbolAttribute(MCSymbol* Symbol, MCSymbolAttr Attribute) override {
    return dispatch(&StreamerBase::emit_symbol_attribute, wrap(Symbol),
                    Attribute);
  }

  void emitSymbolDesc(MCSymbol* Symbol, unsigned DescValue) override {
    dispatch(&StreamerBase::emit_symbol_desc, wrap(Symbol), DescValue);
  }

  void BeginCOFFSymbolDef(const MCSymbol* Symbol) override {
    dispatch(&StreamerBase::begin_coff_symbol_def, wrap(Symbol));
  }

  void EmitCOFFSymbolStorageClass(int StorageClass) override {
    dispatch(&StreamerBase::emit_coff_symbol_storage_class, StorageClass);
  }

  void EmitCOFFSymbolType(int Type) override {
    dispatch(&StreamerBase::emit_coff_symbol_type, Type);
  }

  void EndCOFFSymbolDef() override {
    dispatch(&StreamerBase::end_coff_symbol_def);
  }

  void EmitCOFFSafeSEH(MCSymbol const* Symbol) override {
    dispatch(&StreamerBase::emit_coff_safe_seh, wrap(Symbol));
  }

  void EmitCOFFSymbolIndex(MCSymbol const* Symbol) override {
    dispatch(&StreamerBase::emit_coff_symbol_index, wrap(Symbol));
  }

  void EmitCOFFSectionIndex(MCSymbol const* Symbol) override {
    dispatch(&StreamerBase::emit_coff_section_index, wrap(Symbol));
  }

  void EmitCOFFSecRel32(MCSymbol const* Symbol, uint64_t Offset) override {
    dispatch(&StreamerBase::emit_coff_secprel32, wrap(Symbol), Offset);
  }

  void EmitCOFFImgRel32(MCSymbol const* Symbol, int64_t Offset) override {
    dispatch(&StreamerBase::emit_coff_imgprel32, wrap(Symbol), Offset);
  }

  void emitXCOFFLocalCommonSymbol(MCSymbol* LabelSym, uint64_t Size,
                                  MCSymbol* CsectSym,
                                  unsigned ByteAlignment) override {
    dispatch(&StreamerBase::emit_xcoff_local_common_symbol, wrap(LabelSym),
             Size, wrap(CsectSym), ByteAlignment);
  }

  void emitXCOFFSymbolLinkageWithVisibility(MCSymbol* Symbol,
                                            MCSymbolAttr Linkage,
                                            MCSymbolAttr Visibility) override {
    dispatch(&StreamerBase::emit_xcoff_symbol_linkage_with_visibility,
             wrap(Symbol), Linkage, Visibility);
  }

  void emitXCOFFRenameDirective(const MCSymbol* Name,
                                StringRef Rename) override {
    dispatch(&StreamerBase::emit_xcoff_rename_directive, wrap(Name), Rename);
  }

  void emitELFSize(MCSymbol* Symbol, const MCExpr* Value) override {
    dispatch(&StreamerBase::emit_elf_size, wrap(Symbol), wrap(Value));
  }

  void emitELFSymverDirective(const MCSymbol* OriginalSym, StringRef Name,
                              bool KeepOriginalSym) override {
    dispatch(&StreamerBase::emit_elf_symver_directive, wrap(OriginalSym), Name,
             KeepOriginalSym);
  }

#if NOT_IMPLEMENTED
  void emitLOHDirective(MCLOHType Kind, const MCLOHArgs& Args) override {
    dispatch(&StreamerBase::emit_loh_directive, wrap(Kind), wrap(Args));
  }
#endif

  void emitGNUAttribute(unsigned Tag, unsigned Value) override {
    dispatch(&StreamerBase::emit_gnu_attribute, Tag, Value);
  }

  void emitCommonSymbol(MCSymbol* Symbol, uint64_t Size,
                        unsigned ByteAlignment) override {
    dispatch(&StreamerBase::emit_common_symbol, wrap(Symbol), Size,
             ByteAlignment);
  }

  void emitLocalCommonSymbol(MCSymbol* Symbol, uint64_t Size,
                             unsigned ByteAlignment) override {
    dispatch(&StreamerBase::emit_local_common_symbol, wrap(Symbol), Size,
             ByteAlignment);
  }

  void emitZerofill(MCSection* Section, MCSymbol* Symbol = nullptr,
                    uint64_t Size = 0, unsigned ByteAlignment = 0,
                    SMLoc Loc = SMLoc()) override {
    dispatch(&StreamerBase::emit_zero_fill, wrap(Section), wrap(Symbol), Size,
             ByteAlignment, wrap(Loc));
  }

  void emitTBSSSymbol(MCSection* Section, MCSymbol* Symbol, uint64_t Size,
                      unsigned ByteAlignment = 0) override {
    dispatch(&StreamerBase::emit_tbss_symbol, wrap(Section), wrap(Symbol), Size,
             ByteAlignment);
  }

  void emitBytes(StringRef Data) override {
    dispatch(&StreamerBase::emit_bytes, py::bytes(Data.data(), Data.size()));
  }

  void emitBinaryData(StringRef Data) override {
    dispatch(&StreamerBase::emit_binary_data,
             py::bytes(Data.data(), Data.size()));
  }

  void emitValueImpl(const MCExpr* Value, unsigned Size,
                     SMLoc Loc = SMLoc()) override {
    dispatch(&StreamerBase::emit_value_impl, wrap(Value), Size, wrap(Loc));
  }

  void emitIntValue(uint64_t Value, unsigned Size) override {
    dispatch(&StreamerBase::emit_int_value, Value, Size);
  }

#if NOT_IMPLEMENTED
  void emitIntValue(APInt Value) override {
  dispatch(&StreamerBase::emit_int_value, ?);
  }
#endif

  void emitIntValueInHex(uint64_t Value, unsigned Size) override {
    dispatch(&StreamerBase::emit_int_value_in_hex, Value, Size);
  }

  void emitIntValueInHexWithPadding(uint64_t Value, unsigned Size) override {
    dispatch(&StreamerBase::emit_int_value_in_hex_with_padding, Value, Size);
  }

  void emitULEB128Value(const MCExpr* Value) override {
    dispatch(&StreamerBase::emit_uleb128_value, wrap(Value));
  }

  void emitSLEB128Value(const MCExpr* Value) override {
    dispatch(&StreamerBase::emit_sleb128_value, wrap(Value));
  }

  void emitDTPRel64Value(const MCExpr* Value) override {
    dispatch(&StreamerBase::emit_dtprel64_value, wrap(Value));
  }

  void emitDTPRel32Value(const MCExpr* Value) override {
    dispatch(&StreamerBase::emit_dtprel32_value, wrap(Value));
  }

  void emitTPRel64Value(const MCExpr* Value) override {
    dispatch(&StreamerBase::emit_tprel64_value, wrap(Value));
  }

  void emitTPRel32Value(const MCExpr* Value) override {
    dispatch(&StreamerBase::emit_tprel32_value, wrap(Value));
  }

  void emitGPRel64Value(const MCExpr* Value) override {
    dispatch(&StreamerBase::emit_gprel64_value, wrap(Value));
  }

  void emitGPRel32Value(const MCExpr* Value) override {
    dispatch(&StreamerBase::emit_gprel32_value, wrap(Value));
  }

  void emitFill(const MCExpr& NumBytes, uint64_t FillValue,
                SMLoc Loc = SMLoc()) override {
    dispatch(&StreamerBase::emit_value_fill, wrap(&NumBytes), FillValue,
             wrap(Loc));
  }

  void emitFill(const MCExpr& NumValues, int64_t Size, int64_t Expr,
                SMLoc Loc = SMLoc()) override {
    dispatch(&StreamerBase::emit_expr_fill, wrap(&NumValues), Size, Expr,
             wrap(Loc));
  }

  void emitNops(int64_t NumBytes, int64_t ControlledNopLength,
                SMLoc Loc) override {
    dispatch(&StreamerBase::emit_nops, NumBytes, ControlledNopLength,
             wrap(Loc));
  }

  void emitValueToAlignment(unsigned ByteAlignment, int64_t Value = 0,
                            unsigned ValueSize = 1,
                            unsigned MaxBytesToEmit = 0) override {
    dispatch(&StreamerBase::emit_value_to_alignment, ByteAlignment, Value,
             ValueSize, MaxBytesToEmit);
  }

  void emitCodeAlignment(unsigned ByteAlignment,
                         unsigned MaxBytesToEmit = 0) override {
    dispatch(&StreamerBase::emit_code_alignment, ByteAlignment, MaxBytesToEmit);
  }

  void emitValueToOffset(const MCExpr* Offset, unsigned char Value,
                         SMLoc Loc) override {
    dispatch(&StreamerBase::emit_value_to_offset, wrap(Offset), Value,
             wrap(Loc));
  }

#if NOT_IMPLEMENTED
  void emitFileDirective(StringRef Filename) override {
    dispatch(&StreamerBase::emit_file_directive, Filename);
  }

  void emitFileDirective(StringRef Filename, StringRef CompilerVerion,
                         StringRef TimeStamp, StringRef Description) override {
    dispatch(&StreamerBase::emit_file_directive, Filename, CompilerVerion,
             TimeStamp, Description);
  }
#endif

  void emitIdent(StringRef IdentString) override {
    dispatch(&StreamerBase::emit_ident, IdentString);
  }

#if NOT_IMPLEMENTED
  Expected<unsigned> tryEmitDwarfFileDirective(
      unsigned FileNo, StringRef Directory, StringRef Filename,
      Optional<MD5::MD5Result> Checksum = None,
      Optional<StringRef> Source = None, unsigned CUID = 0) override {
  return dispatch(&StreamerBase::try_emit_dwarf_file_directive, FileNo, Directory, Filename, ?, ?, CUID);
  }

  void emitDwarfFile0Directive(StringRef Directory, StringRef Filename,
                               Optional<MD5::MD5Result> Checksum,
                               Optional<StringRef> Source,
                               unsigned CUID = 0) override {
  dispatch(&StreamerBase::emit_dwarf_file_0_directive, Directory, Filename, ?, ?, CUID);
  }
#endif

  void emitCFIBKeyFrame() override {
    dispatch(&StreamerBase::emit_cfi_b_key_frame);
  }

  void emitDwarfLocDirective(unsigned FileNo, unsigned Line, unsigned Column,
                             unsigned Flags, unsigned Isa,
                             unsigned Discriminator,
                             StringRef FileName) override {
    dispatch(&StreamerBase::emit_dwarf_loc_directive, FileNo, Line, Column,
             Flags, Isa, Discriminator, FileName);
  }

#if NOT_IMPLEMENTED
  bool EmitCVFileDirective(unsigned FileNo, StringRef Filename,
                           ArrayRef<uint8_t> Checksum,
                           unsigned ChecksumKind) override {
  return dispatch(&StreamerBase::emit_cv_file_directive, FileNo, Filename, ?, ChecksumKind);
  }
#endif

  bool EmitCVFuncIdDirective(unsigned FunctionId) override {
    return dispatch(&StreamerBase::emit_cv_func_id_directive, FunctionId);
  }

  bool EmitCVInlineSiteIdDirective(unsigned FunctionId, unsigned IAFunc,
                                   unsigned IAFile, unsigned IALine,
                                   unsigned IACol, SMLoc Loc) override {
    return dispatch(&StreamerBase::emit_cv_inline_site_id_directive, FunctionId,
                    IAFunc, IAFile, IALine, IACol, wrap(Loc));
  }

  void emitCVLocDirective(unsigned FunctionId, unsigned FileNo, unsigned Line,
                          unsigned Column, bool PrologueEnd, bool IsStmt,
                          StringRef FileName, SMLoc Loc) override {
    dispatch(&StreamerBase::emit_cv_loc_directive, FunctionId, FileNo, Line,
             Column, PrologueEnd, IsStmt, FileName, wrap(Loc));
  }

  void emitCVLinetableDirective(unsigned FunctionId, const MCSymbol* FnStart,
                                const MCSymbol* FnEnd) override {
    dispatch(&StreamerBase::emit_cv_line_table_directive, FunctionId,
             wrap(FnStart), wrap(FnEnd));
  }

  void emitCVInlineLinetableDirective(unsigned PrimaryFunctionId,
                                      unsigned SourceFileId,
                                      unsigned SourceLineNum,
                                      const MCSymbol* FnStartSym,
                                      const MCSymbol* FnEndSym) override {
    dispatch(&StreamerBase::emit_cv_inline_line_table_directive,
             PrimaryFunctionId, SourceFileId, SourceLineNum, wrap(FnStartSym),
             wrap(FnEndSym));
  }

#if NOT_IMPLEMENTED
  void emitCVDefRangeDirective(
      ArrayRef<std::pair<const MCSymbol*, const MCSymbol*>> Ranges,
      StringRef FixedSizePortion) override {
  dispatch(&StreamerBase::emit_cv_def_range_directive, ?, FixedSizePortion);
  }

  void emitCVDefRangeDirective(
      ArrayRef<std::pair<const MCSymbol*, const MCSymbol*>> Ranges,
      codeview::DefRangeRegisterRelHeader DRHdr) override {
  dispatch(&StreamerBase::emit_cv_def_range_directive, ?, ?);
  }

  void emitCVDefRangeDirective(
      ArrayRef<std::pair<const MCSymbol*, const MCSymbol*>> Ranges,
      codeview::DefRangeSubfieldRegisterHeader DRHdr) override {
  dispatch(&StreamerBase::emit_cv_def_range_directive, ?, ?);
  }

  void emitCVDefRangeDirective(
      ArrayRef<std::pair<const MCSymbol*, const MCSymbol*>> Ranges,
      codeview::DefRangeRegisterHeader DRHdr) override {
  dispatch(&StreamerBase::emit_cv_def_range_directive, ?, ?);
  }

  void emitCVDefRangeDirective(
      ArrayRef<std::pair<const MCSymbol*, const MCSymbol*>> Ranges,
      codeview::DefRangeFramePointerRelHeader DRHdr) override {
  dispatch(&StreamerBase::emit_cv_def_range_directive, ?, ?);
  }
#endif

  void emitCVStringTableDirective() override {
    dispatch(&StreamerBase::emit_cv_string_table_directive);
  }

  void emitCVFileChecksumsDirective() override {
    dispatch(&StreamerBase::emit_cv_file_checksums_directive);
  }

  void emitCVFileChecksumOffsetDirective(unsigned FileNo) override {
    dispatch(&StreamerBase::emit_cv_file_checksum_offset_directive, FileNo);
  }

  void EmitCVFPOData(const MCSymbol* ProcSym, SMLoc Loc = {}) override {
    dispatch(&StreamerBase::emit_cv_fpo_data, wrap(ProcSym), wrap(Loc));
  }

  void emitAbsoluteSymbolDiff(const MCSymbol* Hi, const MCSymbol* Lo,
                              unsigned Size) override {
    dispatch(&StreamerBase::emit_absolute_symbol_diff, wrap(Hi), wrap(Lo),
             Size);
  }

  void emitAbsoluteSymbolDiffAsULEB128(const MCSymbol* Hi,
                                       const MCSymbol* Lo) override {
    dispatch(&StreamerBase::emit_absolute_symbol_diff_as_uleb128, wrap(Hi),
             wrap(Lo));
  }

  MCSymbol* getDwarfLineTableSymbol(unsigned CUID) override {
    return unwrap(dispatch(&StreamerBase::get_dwarf_line_table_symbol, CUID));
  }

  void emitCFISections(bool EH, bool Debug) override {
    dispatch(&StreamerBase::emit_cfi_sections, EH, Debug);
  }

  void emitCFIDefCfa(int64_t Register, int64_t Offset) override {
    dispatch(&StreamerBase::emit_cfi_def_cfa, Register, Offset);
  }

  void emitCFIDefCfaOffset(int64_t Offset) override {
    dispatch(&StreamerBase::emit_cfi_def_cfa_offset, Offset);
  }

  void emitCFIDefCfaRegister(int64_t Register) override {
    dispatch(&StreamerBase::emit_cfi_def_cfa_register, Register);
  }

  void emitCFILLVMDefAspaceCfa(int64_t Register, int64_t Offset,
                               int64_t AddressSpace) override {
    dispatch(&StreamerBase::emit_cfi_llvm_def_aspace_cfa, Register, Offset,
             AddressSpace);
  }

  void emitCFIOffset(int64_t Register, int64_t Offset) override {
    dispatch(&StreamerBase::emit_cfi_offset, Register, Offset);
  }

  void emitCFIPersonality(const MCSymbol* Sym, unsigned Encoding) override {
    dispatch(&StreamerBase::emit_cfi_personality, wrap(Sym), Encoding);
  }

  void emitCFILsda(const MCSymbol* Sym, unsigned Encoding) override {
    dispatch(&StreamerBase::emit_cfi_lsda, wrap(Sym), Encoding);
  }

  void emitCFIRememberState() override {
    dispatch(&StreamerBase::emit_cfi_remember_state);
  }

  void emitCFIRestoreState() override {
    dispatch(&StreamerBase::emit_cfi_restore_state);
  }

  void emitCFISameValue(int64_t Register) override {
    dispatch(&StreamerBase::emit_cfi_same_value, Register);
  }

  void emitCFIRestore(int64_t Register) override {
    dispatch(&StreamerBase::emit_cfi_restore, Register);
  }

  void emitCFIRelOffset(int64_t Register, int64_t Offset) override {
    dispatch(&StreamerBase::emit_cfi_rel_offset, Register, Offset);
  }

  void emitCFIAdjustCfaOffset(int64_t Adjustment) override {
    dispatch(&StreamerBase::emit_cfi_adjust_cfa_offset, Adjustment);
  }

  void emitCFIEscape(StringRef Values) override {
    dispatch(&StreamerBase::emit_cfi_escape, Values);
  }

  void emitCFIReturnColumn(int64_t Register) override {
    dispatch(&StreamerBase::emit_cfi_return_column, Register);
  }

  void emitCFIGnuArgsSize(int64_t Size) override {
    dispatch(&StreamerBase::emit_cfi_gnu_args_size, Size);
  }

  void emitCFISignalFrame() override {
    dispatch(&StreamerBase::emit_cfi_signal_frame);
  }

  void emitCFIUndefined(int64_t Register) override {
    dispatch(&StreamerBase::emit_cfi_undefined, Register);
  }

  void emitCFIRegister(int64_t Register1, int64_t Register2) override {
    dispatch(&StreamerBase::emit_cfi_register, Register1, Register2);
  }

  void emitCFIWindowSave() override {
    dispatch(&StreamerBase::emit_cfi_window_save);
  }

  void emitCFINegateRAState() override {
    dispatch(&StreamerBase::emit_cfi_negate_ra_state);
  }

  void EmitWinCFIStartProc(const MCSymbol* Symbol,
                           SMLoc Loc = SMLoc()) override {
    dispatch(&StreamerBase::emit_win_cfi_start_proc, wrap(Symbol), wrap(Loc));
  }

  void EmitWinCFIEndProc(SMLoc Loc = SMLoc()) override {
    dispatch(&StreamerBase::emit_win_cfi_end_proc, wrap(Loc));
  }

  void EmitWinCFIFuncletOrFuncEnd(SMLoc Loc = SMLoc()) override {
    dispatch(&StreamerBase::emit_win_cfi_funclet_or_func_end, wrap(Loc));
  }

  void EmitWinCFIStartChained(SMLoc Loc = SMLoc()) override {
    dispatch(&StreamerBase::emit_win_cfi_start_chained, wrap(Loc));
  }

  void EmitWinCFIEndChained(SMLoc Loc = SMLoc()) override {
    dispatch(&StreamerBase::emit_win_cfi_end_chained, wrap(Loc));
  }

  void EmitWinCFIPushReg(MCRegister Register, SMLoc Loc = SMLoc()) override {
    dispatch(&StreamerBase::emit_win_cfi_push_reg, wrap(Register), wrap(Loc));
  }

  void EmitWinCFISetFrame(MCRegister Register, unsigned Offset,
                          SMLoc Loc = SMLoc()) override {
    dispatch(&StreamerBase::emit_win_cfi_set_frame, wrap(Register), Offset,
             wrap(Loc));
  }

  void EmitWinCFIAllocStack(unsigned Size, SMLoc Loc = SMLoc()) override {
    dispatch(&StreamerBase::emit_win_cfi_alloc_stack, Size, wrap(Loc));
  }

  void EmitWinCFISaveReg(MCRegister Register, unsigned Offset,
                         SMLoc Loc = SMLoc()) override {
    dispatch(&StreamerBase::emit_win_cfi_save_reg, wrap(Register), Offset,
             wrap(Loc));
  }

  void EmitWinCFISaveXMM(MCRegister Register, unsigned Offset,
                         SMLoc Loc = SMLoc()) override {
    dispatch(&StreamerBase::emit_win_cfi_save_xmm, wrap(Register), Offset,
             wrap(Loc));
  }

  void EmitWinCFIPushFrame(bool Code, SMLoc Loc = SMLoc()) override {
    dispatch(&StreamerBase::emit_win_cfi_push_frame, Code, wrap(Loc));
  }

  void EmitWinCFIEndProlog(SMLoc Loc = SMLoc()) override {
    dispatch(&StreamerBase::emit_win_cfi_end_prolog, wrap(Loc));
  }

  void EmitWinEHHandler(const MCSymbol* Sym, bool Unwind, bool Except,
                        SMLoc Loc = SMLoc()) override {
    dispatch(&StreamerBase::emit_win_eh_handler, wrap(Sym), Unwind, Except,
             wrap(Loc));
  }

  void EmitWinEHHandlerData(SMLoc Loc = SMLoc()) override {
    dispatch(&StreamerBase::emit_win_eh_handler_data, wrap(Loc));
  }

  void emitCGProfileEntry(const MCSymbolRefExpr* From,
                          const MCSymbolRefExpr* To, uint64_t Count) override {
    dispatch(&StreamerBase::emit_cg_profile_entry, wrap(From), wrap(To), Count);
  }

  void emitSyntaxDirective() override {
    dispatch(&StreamerBase::emit_syntax_directive);
  }

#if NOT_IMPLEMENTED
  Optional<std::pair<bool, std::string>>
  emitRelocDirective(const MCExpr& Offset, StringRef Name, const MCExpr* Expr,
                     SMLoc Loc, const MCSubtargetInfo& STI) override {
    return dispatch(&StreamerBase::emit_reloc_directive, wrap(Offset), Name,
                    wrap(Expr), wrap(Loc), wrap(STI));
  }
#endif

  void emitAddrsig() override { dispatch(&StreamerBase::emit_addrsig); }

  void emitAddrsigSym(const MCSymbol* Sym) override {
    dispatch(&StreamerBase::emit_addrsig_sym, wrap(Sym));
  }

#if NOT_IMPLEMENTED
  void emitPseudoProbe(uint64_t Guid, uint64_t Index, uint64_t Type,
                       uint64_t Attr,
                       const MCPseudoProbeInlineStack& InlineStack) override {
    dispatch(&StreamerBase::emit_pseudo_probe, Guid, Index, Type, Attr,
             wrap(InlineStack));
  }
#endif

  void emitBundleAlignMode(unsigned AlignPow2) override {
    dispatch(&StreamerBase::emit_bundle_align_mode, AlignPow2);
  }

  void emitBundleLock(bool AlignToEnd) override {
    dispatch(&StreamerBase::emit_bundle_lock, AlignToEnd);
  }

  void emitBundleUnlock() override {
    dispatch(&StreamerBase::emit_bundle_unlock);
  }

#if NOT_IMPLEMENTED
  void emitDwarfUnitLength(uint64_t Length, const Twine& Comment) override {
  dispatch(&StreamerBase::emit_dwarf_unit_length, Length, ?);
  }

  MCSymbol* emitDwarfUnitLength(const Twine& Prefix,
                                const Twine& Comment) override {
  return dispatch(&StreamerBase::emit_dwarf_unit_length, ?, ?);
  }
#endif

  void emitDwarfLineStartLabel(MCSymbol* StartSym) override {
    dispatch(&StreamerBase::emit_dwarf_line_start_label, wrap(StartSym));
  }

  void emitDwarfLineEndEntry(MCSection* Section, MCSymbol* LastLabel) override {
    dispatch(&StreamerBase::emit_dwarf_line_end_entry, wrap(Section),
             wrap(LastLabel));
  }

  void emitDwarfAdvanceLineAddr(int64_t LineDelta, const MCSymbol* LastLabel,
                                const MCSymbol* Label,
                                unsigned PointerSize) override {
    dispatch(&StreamerBase::emit_dwarf_advance_line_addr, LineDelta,
             wrap(LastLabel), wrap(Label), PointerSize);
  }

  void emitInstruction(const MCInst& Inst,
                       const MCSubtargetInfo& STI) override {
    if (auto State = WeakState.lock()) {
      SmallVector<MCFixup, 4> Fixups;
      SmallString<32> Code;
      raw_svector_ostream VecOS(Code);
      State->CE->encodeInstruction(Inst, VecOS, Fixups, STI);

      std::vector<std::shared_ptr<mc::Fixup>> FixupsVec;
      std::transform(Fixups.begin(), Fixups.end(),
                     std::back_inserter(FixupsVec),
                     [&](const MCFixup& Fixup) { return wrap(Fixup); });

      dispatch(&StreamerBase::emit_instruction, wrap(Inst),
               py::bytes(Code.data(), Code.size()), FixupsVec);
    }
  }

  void diagCallback(const SMDiagnostic& Diag) {
    dispatch(&StreamerBase::diagnostic, wrap(Diag));
  }

private:
  template <typename T>
  auto wrap(T&& Value) -> decltype(mc::wrap(WeakState.lock(), Value)) {
    std::shared_ptr<ParserState> State = WeakState.lock();
    return mc::wrap(State, Value);
  }
};

class Assembler {
public:
  Assembler(std::string TripleStr) {
    InitLLVM();

    TheTriple = Triple(Triple::normalize(TripleStr));

    std::string Error;
    TheTarget = TargetRegistry::lookupTarget(TheTriple.getTriple(), Error);

    if (!TheTarget)
      throw py::value_error(Error);
  }

  bool assemble(StreamerBase& Streamer, std::string Asm) const {
    auto State = std::make_shared<ParserState>();
    State->TheTriple = TheTriple;
    State->MRI.reset(TheTarget->createMCRegInfo(TheTriple.getTriple()));
    State->MAI.reset(TheTarget->createMCAsmInfo(
        *State->MRI, TheTriple.getTriple(), State->MCOptions));

    State->MCII.reset(TheTarget->createMCInstrInfo());
    State->STI.reset(TheTarget->createMCSubtargetInfo(
        TheTriple.getTriple(), /*MCPU=*/"", /*FeaturesStr=*/""));
    State->MAB.reset(TheTarget->createMCAsmBackend(*State->STI, *State->MRI,
                                                   State->MCOptions));

    State->SM.AddNewSourceBuffer(MemoryBuffer::getMemBuffer(Asm), SMLoc());

    State->Ctx = std::make_unique<MCContext>(TheTriple, State->MAI.get(),
                                             State->MRI.get(), State->STI.get(),
                                             &State->SM, &State->MCOptions);
    State->MOFI.reset(
        TheTarget->createMCObjectFileInfo(*State->Ctx, /*PIC=*/false));
    State->Ctx->setObjectFileInfo(State->MOFI.get());

    State->CE.reset(
        TheTarget->createMCCodeEmitter(*State->MCII, *State->MRI, *State->Ctx));
    State->Str = std::make_unique<StreamerAdaptor>(State, Streamer);
    State->Str->setUseAssemblerInfoForParsing(true);
    State->SM.setDiagHandler(&DiagCallback, State->Str.get());

    State->Parser.reset(
        createMCAsmParser(State->SM, *State->Ctx, *State->Str, *State->MAI));
    State->TAP.reset(TheTarget->createMCAsmParser(
        *State->STI, *State->Parser, *State->MCII, State->MCOptions));
    if (!State->TAP)
      throw py::value_error("unsupported target");

    // There doesn't really exist great symbolic constants for the dialects.
    if (TheTriple.isX86()) {
      switch (Syntax) {
      case X86Syntax::ATT:
        State->Parser->setAssemblerDialect(0);
        break;
      case X86Syntax::INTEL:
        State->Parser->setAssemblerDialect(1);
        break;
      }
    }

    State->Parser->setTargetParser(*State->TAP);

    int Res = State->Parser->Run(/*NoInitialTextSection=*/false);
    if (PyErr_Occurred())
      throw py::error_already_set();
    return Res == 0;
  }

  X86Syntax get_x86_syntax() const { return Syntax; }
  void set_x86_syntax(X86Syntax Value) { Syntax = Value; }

  static std::string default_target() { return sys::getDefaultTargetTriple(); }

private:
  static void DiagCallback(const SMDiagnostic& Diag, void* Context) {
    static_cast<StreamerAdaptor*>(Context)->diagCallback(Diag);
  }

  const Target* TheTarget = nullptr;
  Triple TheTriple;
  X86Syntax Syntax = X86Syntax::ATT;
};

PYBIND11_MODULE(_core, m) {
  // clang-format off
  InitLLVM();

  mc::register_module(m);

  py::class_<ParserState, std::shared_ptr<ParserState>>(m, "ParserState")
      .def_property_readonly("loc", [](std::shared_ptr<ParserState> State) {
        return mc::wrap(State, State->Str->getStartTokLoc());
      });

  py::class_<StreamerBase, PyStreamer>(m, "Streamer")
      .def(py::init<>())
      .def("emit_cfi_start_proc_impl",
           &StreamerBase::emit_cfi_start_proc_impl,
           "state"_a, "frame"_a)
      .def("emit_cfi_end_proc_impl",
           &StreamerBase::emit_cfi_end_proc_impl,
           "state"_a, "cur_frame"_a)
#if NOT_IMPLEMENTED
      .def("emit_windows_unwind_tables",
           &StreamerBase::emit_windows_unwind_tables,
           "state"_a, "frame"_a)
      .def("emit_windows_unwind_tables",
           &StreamerBase::emit_windows_unwind_tables,
           "state"_a)
#endif
      .def("emit_raw_text_impl",
           &StreamerBase::emit_raw_text_impl,
           "state"_a, "string"_a)
#if NOT_IMPLEMENTED
      .def("emit_cfi_label",
           &StreamerBase::emit_cfi_label,
           "state"_a)
#endif
      .def("add_comment",
           &StreamerBase::add_comment,
           "state"_a, "comment"_a, "eol"_a)
      .def("emit_raw_comment",
           &StreamerBase::emit_raw_comment,
           "state"_a, "comment"_a, "tab_prefix"_a)
      .def("add_explicit_comment",
           &StreamerBase::add_explicit_comment,
           "state"_a, "comment"_a)
      .def("emit_explicit_comments",
           &StreamerBase::emit_explicit_comments,
           "state"_a)
      .def("change_section",
           &StreamerBase::change_section,
           "state"_a, "section"_a, "subsection"_a)
      .def("init_sections",
           &StreamerBase::init_sections,
           "state"_a, "no_exec_stack"_a)
      .def("emit_label",
           &StreamerBase::emit_label,
           "state"_a, "symbol"_a, "loc"_a)
      .def("emit_eh_sym_attributes",
           &StreamerBase::emit_eh_sym_attributes,
           "state"_a, "symbol"_a, "eh_symbol"_a)
      .def("emit_assembler_flag",
           &StreamerBase::emit_assembler_flag,
           "state"_a, "flag"_a)
      .def("emit_linker_options",
           &StreamerBase::emit_linker_options,
           "state"_a, "kind"_a)
      .def("emit_data_region",
           &StreamerBase::emit_data_region,
           "state"_a, "kind"_a)
#if NOT_IMPLEMENTED
      .def("emit_version_min",
           &StreamerBase::emit_version_min,
           "state"_a, "type"_a, "major"_a, "minor"_a, "update"_a,
           "sdk_version"_a)
      .def("emit_build_version",
           &StreamerBase::emit_build_version,
           "state"_a, "platform"_a, "major"_a, "minor"_a, "update"_a,
           "sdk_version"_a)
#endif
      .def("emit_thumb_func",
           &StreamerBase::emit_thumb_func,
           "state"_a, "func"_a)
      .def("emit_assignment",
           &StreamerBase::emit_assignment,
           "state"_a, "symbol"_a, "value"_a)
      .def("emit_weak_reference",
           &StreamerBase::emit_weak_reference,
           "state"_a, "alias"_a, "symbol"_a)
      .def("emit_symbol_attribute",
           &StreamerBase::emit_symbol_attribute,
           "state"_a, "symbol"_a, "attribute"_a)
      .def("emit_symbol_desc",
           &StreamerBase::emit_symbol_desc,
           "state"_a, "symbol"_a, "desc_value"_a)
      .def("begin_coff_symbol_def",
           &StreamerBase::begin_coff_symbol_def,
           "state"_a, "symbol"_a)
      .def("emit_coff_symbol_storage_class",
           &StreamerBase::emit_coff_symbol_storage_class,
           "state"_a, "storage_class"_a)
      .def("emit_coff_symbol_type",
           &StreamerBase::emit_coff_symbol_type,
           "state"_a, "type"_a)
      .def("end_coff_symbol_def",
           &StreamerBase::end_coff_symbol_def,
           "state"_a)
      .def("emit_coff_safe_seh",
           &StreamerBase::emit_coff_safe_seh,
           "state"_a, "symbol"_a)
      .def("emit_coff_symbol_index",
           &StreamerBase::emit_coff_symbol_index,
           "state"_a, "symbol"_a)
      .def("emit_coff_section_index",
           &StreamerBase::emit_coff_section_index,
           "state"_a, "symbol"_a)
      .def("emit_coff_secprel32",
           &StreamerBase::emit_coff_secprel32,
           "state"_a, "symbol"_a, "offset"_a)
      .def("emit_coff_imgprel32",
           &StreamerBase::emit_coff_imgprel32,
           "state"_a, "symbol"_a, "offset"_a)
      .def("emit_xcoff_local_common_symbol",
           &StreamerBase::emit_xcoff_local_common_symbol,
           "state"_a, "label_sym"_a, "size"_a, "c_sect_sym"_a,
           "byte_alignment"_a)
      .def("emit_xcoff_symbol_linkage_with_visibility",
           &StreamerBase::emit_xcoff_symbol_linkage_with_visibility,
           "state"_a,
           "symbol"_a,
           "linkage"_a,
           "visibility"_a)
      .def("emit_xcoff_rename_directive",
           &StreamerBase::emit_xcoff_rename_directive,
           "state"_a,
           "name"_a,
           "rename"_a)
      .def("emit_elf_size",
           &StreamerBase::emit_elf_size,
           "state"_a,
           "symbol"_a,
           "value"_a)
      .def("emit_elf_symver_directive",
           &StreamerBase::emit_elf_symver_directive,
           "state"_a,
           "original_sym"_a,
           "name"_a,
           "keep_original_sym"_a)
#if NOT_IMPLEMENTED
      .def("emit_loh_directive",
           &StreamerBase::emit_loh_directive,
           "state"_a, "kind"_a, "args"_a)
#endif
      .def("emit_gnu_attribute",
           &StreamerBase::emit_gnu_attribute,
           "state"_a, "tag"_a, "value"_a)
      .def("emit_common_symbol",
           &StreamerBase::emit_common_symbol,
           "state"_a, "symbol"_a, "size"_a, "byte_alignment"_a)
      .def("emit_local_common_symbol",
           &StreamerBase::emit_local_common_symbol,
           "state"_a, "symbol"_a, "size"_a, "byte_alignment"_a)
      .def("emit_zero_fill",
           &StreamerBase::emit_zero_fill,
           "state"_a, "section"_a, "symbol"_a, "size"_a, "byte_alignment"_a,
           "loc"_a)
      .def("emit_tbss_symbol",
           &StreamerBase::emit_tbss_symbol,
           "state"_a, "section"_a, "symbol"_a, "size"_a, "byte_alignment"_a)
      .def("emit_bytes",
           &StreamerBase::emit_bytes,
           "state"_a, "data"_a)
      .def("emit_binary_data",
           &StreamerBase::emit_binary_data,
           "state"_a, "data"_a)
      .def("emit_value_impl",
           &StreamerBase::emit_value_impl,
           "state"_a, "value"_a, "size"_a, "loc"_a)
      .def("emit_int_value",
           &StreamerBase::emit_int_value,
           "state"_a, "value"_a, "size"_a)
#if NOT_IMPLEMENTED
      .def("emit_int_value",
           &StreamerBase::emit_int_value,
           "state"_a, "value"_a)
#endif
      .def("emit_int_value_in_hex",
           &StreamerBase::emit_int_value_in_hex,
           "state"_a, "value"_a, "size"_a)
      .def("emit_int_value_in_hex_with_padding",
           &StreamerBase::emit_int_value_in_hex_with_padding,
           "state"_a, "value"_a, "size"_a)
      .def("emit_uleb128_value",
           &StreamerBase::emit_uleb128_value,
           "state"_a, "value"_a)
      .def("emit_sleb128_value",
           &StreamerBase::emit_sleb128_value,
           "state"_a, "value"_a)
      .def("emit_dtprel64_value",
           &StreamerBase::emit_dtprel64_value,
           "state"_a, "value"_a)
      .def("emit_dtprel32_value",
           &StreamerBase::emit_dtprel32_value,
           "state"_a, "value"_a)
      .def("emit_tprel64_value",
           &StreamerBase::emit_tprel64_value,
           "state"_a, "value"_a)
      .def("emit_tprel32_value",
           &StreamerBase::emit_tprel32_value,
           "state"_a, "value"_a)
      .def("emit_gprel64_value",
           &StreamerBase::emit_gprel64_value,
           "state"_a, "value"_a)
      .def("emit_gprel32_value",
           &StreamerBase::emit_gprel32_value,
           "state"_a, "value"_a)
      .def("emit_value_fill",
           &StreamerBase::emit_value_fill,
           "state"_a, "num_bytes"_a, "fill_value"_a, "loc"_a)
      .def("emit_expr_fill",
           &StreamerBase::emit_expr_fill,
           "state"_a, "num_values"_a, "size"_a, "expr"_a, "loc"_a)
      .def("emit_nops",
           &StreamerBase::emit_nops,
           "state"_a, "num_bytes"_a, "controlled_nop_length"_a, "loc"_a)
      .def("emit_value_to_alignment",
           &StreamerBase::emit_value_to_alignment,
           "state"_a, "byte_alignment"_a, "value"_a, "value_size"_a,
           "max_bytes_to_emit"_a)
      .def("emit_code_alignment",
           &StreamerBase::emit_code_alignment,
           "state"_a, "byte_alignment"_a, "max_bytes_to_emit"_a)
      .def("emit_value_to_offset",
           &StreamerBase::emit_value_to_offset,
           "state"_a, "offset"_a, "value"_a, "loc"_a)
#if NOT_IMPLEMENTED
      .def("emit_file_directive",
           &StreamerBase::emit_file_directive,
           "state"_a, "filename"_a)
      .def("emit_file_directive",
           &StreamerBase::emit_file_directive,
           "state"_a, "filename"_a, "compiler_version"_a, "timestamp"_a,
           "description"_a)
#endif
      .def("emit_ident",
           &StreamerBase::emit_ident,
           "state"_a,
           "ident_string"_a)
#if NOT_IMPLEMENTED
      .def("try_emit_dwarf_file_directive",
           &StreamerBase::try_emit_dwarf_file_directive,
           "state"_a, "file_no"_a, "directory"_a, "filename"_a, "checksum"_a,
           "source"_a, "c_uid"_a)
      .def("emit_dwarf_file_0_directive",
           &StreamerBase::emit_dwarf_file_0_directive,
           "state"_a, "directory"_a, "filename"_a, "checksum"_a, "source"_a,
           "c_uid"_a)
#endif
      .def("emit_cfi_b_key_frame",
           &StreamerBase::emit_cfi_b_key_frame,
           "state"_a)
      .def("emit_dwarf_loc_directive",
           &StreamerBase::emit_dwarf_loc_directive,
           "state"_a, "file_no"_a, "line"_a, "column"_a, "flags"_a, "isa"_a,
           "discriminator"_a, "file_name"_a)
#if NOT_IMPLEMENTED
      .def("emit_cv_file_directive",
           &StreamerBase::emit_cv_file_directive,
           "state"_a, "file_no"_a, "filename"_a, "checksum"_a,
           "checksum_kind"_a)
#endif
      .def("emit_cv_func_id_directive",
           &StreamerBase::emit_cv_func_id_directive,
           "state"_a,
           "function_id"_a)
      .def("emit_cv_inline_site_id_directive",
           &StreamerBase::emit_cv_inline_site_id_directive,
           "state"_a, "function_id"_a, "ia_func"_a, "ia_file"_a, "ia_line"_a,
           "ia_col"_a, "loc"_a)
      .def("emit_cv_loc_directive",
           &StreamerBase::emit_cv_loc_directive,
           "state"_a, "function_id"_a, "file_no"_a, "line"_a, "column"_a,
           "prologue_end"_a, "is_stmt"_a, "file_name"_a, "loc"_a)
      .def("emit_cv_line_table_directive",
           &StreamerBase::emit_cv_line_table_directive,
           "state"_a, "function_id"_a, "fn_start"_a, "fn_end"_a)
      .def("emit_cv_inline_line_table_directive",
           &StreamerBase::emit_cv_inline_line_table_directive,
           "state"_a, "primary_function_id"_a, "source_file_id"_a,
           "source_line_num"_a, "fn_start_sym"_a, "fn_end_sym"_a)
#if NOT_IMPLEMENTED
      .def("emit_cv_def_range_directive",
           &StreamerBase::emit_cv_def_range_directive,
           "state"_a, "ranges"_a, "fixed_size_portion"_a)
      .def("emit_cv_def_range_directive",
           &StreamerBase::emit_cv_def_range_directive,
           "state"_a, "ranges"_a, "dr_hdr"_a)
      .def("emit_cv_def_range_directive",
           &StreamerBase::emit_cv_def_range_directive,
           "state"_a, "ranges"_a, "dr_hdr"_a)
      .def("emit_cv_def_range_directive",
           &StreamerBase::emit_cv_def_range_directive,
           "state"_a, "ranges"_a, "dr_hdr"_a)
      .def("emit_cv_def_range_directive",
           &StreamerBase::emit_cv_def_range_directive,
           "state"_a, "ranges"_a, "dr_hdr"_a)
#endif
      .def("emit_cv_string_table_directive",
           &StreamerBase::emit_cv_string_table_directive,
           "state"_a)
      .def("emit_cv_file_checksums_directive",
           &StreamerBase::emit_cv_file_checksums_directive,
           "state"_a)
      .def("emit_cv_file_checksum_offset_directive",
           &StreamerBase::emit_cv_file_checksum_offset_directive,
           "state"_a, "file_no"_a)
      .def("emit_cv_fpo_data",
           &StreamerBase::emit_cv_fpo_data,
           "state"_a, "proc_sym"_a, "loc"_a)
      .def("emit_absolute_symbol_diff",
           &StreamerBase::emit_absolute_symbol_diff,
           "state"_a, "hi"_a, "lo"_a, "size"_a)
      .def("emit_absolute_symbol_diff_as_uleb128",
           &StreamerBase::emit_absolute_symbol_diff_as_uleb128,
           "state"_a, "hi"_a, "lo"_a)
      .def("get_dwarf_line_table_symbol",
           &StreamerBase::get_dwarf_line_table_symbol,
           "state"_a, "c_uid"_a)
      .def("emit_cfi_sections",
           &StreamerBase::emit_cfi_sections,
           "state"_a, "eh"_a, "debug"_a)
      .def("emit_cfi_def_cfa",
           &StreamerBase::emit_cfi_def_cfa,
           "state"_a, "register"_a, "offset"_a)
      .def("emit_cfi_def_cfa_offset",
           &StreamerBase::emit_cfi_def_cfa_offset,
           "state"_a, "offset"_a)
      .def("emit_cfi_def_cfa_register",
           &StreamerBase::emit_cfi_def_cfa_register,
           "state"_a, "register"_a)
      .def("emit_cfi_llvm_def_aspace_cfa",
           &StreamerBase::emit_cfi_llvm_def_aspace_cfa,
           "state"_a, "register"_a, "offset"_a, "address_space"_a)
      .def("emit_cfi_offset",
           &StreamerBase::emit_cfi_offset,
           "state"_a, "register"_a, "offset"_a)
      .def("emit_cfi_personality",
           &StreamerBase::emit_cfi_personality,
           "state"_a, "sym"_a, "encoding"_a)
      .def("emit_cfi_lsda",
           &StreamerBase::emit_cfi_lsda,
           "state"_a, "sym"_a, "encoding"_a)
      .def("emit_cfi_remember_state",
           &StreamerBase::emit_cfi_remember_state,
           "state"_a)
      .def("emit_cfi_restore_state",
           &StreamerBase::emit_cfi_restore_state,
           "state"_a)
      .def("emit_cfi_same_value",
           &StreamerBase::emit_cfi_same_value,
           "state"_a, "register"_a)
      .def("emit_cfi_restore",
           &StreamerBase::emit_cfi_restore,
           "state"_a, "register"_a)
      .def("emit_cfi_rel_offset",
           &StreamerBase::emit_cfi_rel_offset,
           "state"_a, "register"_a, "offset"_a)
      .def("emit_cfi_adjust_cfa_offset",
           &StreamerBase::emit_cfi_adjust_cfa_offset,
           "state"_a, "adjustment"_a)
      .def("emit_cfi_escape",
           &StreamerBase::emit_cfi_escape,
           "state"_a, "values"_a)
      .def("emit_cfi_return_column",
           &StreamerBase::emit_cfi_return_column,
           "state"_a, "register"_a)
      .def("emit_cfi_gnu_args_size",
           &StreamerBase::emit_cfi_gnu_args_size,
           "state"_a, "size"_a)
      .def("emit_cfi_signal_frame",
           &StreamerBase::emit_cfi_signal_frame,
           "state"_a)
      .def("emit_cfi_undefined",
           &StreamerBase::emit_cfi_undefined,
           "state"_a, "register"_a)
      .def("emit_cfi_register",
           &StreamerBase::emit_cfi_register,
           "state"_a, "register_1"_a, "register_2"_a)
      .def("emit_cfi_window_save",
           &StreamerBase::emit_cfi_window_save,
           "state"_a)
      .def("emit_cfi_negate_ra_state",
           &StreamerBase::emit_cfi_negate_ra_state,
           "state"_a)
      .def("emit_win_cfi_start_proc",
           &StreamerBase::emit_win_cfi_start_proc,
           "state"_a, "symbol"_a, "loc"_a)
      .def("emit_win_cfi_end_proc",
           &StreamerBase::emit_win_cfi_end_proc,
           "state"_a, "loc"_a)
      .def("emit_win_cfi_funclet_or_func_end",
           &StreamerBase::emit_win_cfi_funclet_or_func_end,
           "state"_a, "loc"_a)
      .def("emit_win_cfi_start_chained",
           &StreamerBase::emit_win_cfi_start_chained,
           "state"_a, "loc"_a)
      .def("emit_win_cfi_end_chained",
           &StreamerBase::emit_win_cfi_end_chained,
           "state"_a, "loc"_a)
      .def("emit_win_cfi_push_reg",
           &StreamerBase::emit_win_cfi_push_reg,
           "state"_a, "register"_a, "loc"_a)
      .def("emit_win_cfi_set_frame",
           &StreamerBase::emit_win_cfi_set_frame,
           "state"_a, "register"_a, "offset"_a, "loc"_a)
      .def("emit_win_cfi_alloc_stack",
           &StreamerBase::emit_win_cfi_alloc_stack,
           "state"_a, "size"_a, "loc"_a)
      .def("emit_win_cfi_save_reg",
           &StreamerBase::emit_win_cfi_save_reg,
           "state"_a, "register"_a, "offset"_a, "loc"_a)
      .def("emit_win_cfi_save_xmm",
           &StreamerBase::emit_win_cfi_save_xmm,
           "state"_a, "register"_a, "offset"_a, "loc"_a)
      .def("emit_win_cfi_push_frame",
           &StreamerBase::emit_win_cfi_push_frame,
           "state"_a, "code"_a, "loc"_a)
      .def("emit_win_cfi_end_prolog",
           &StreamerBase::emit_win_cfi_end_prolog,
           "state"_a, "loc"_a)
      .def("emit_win_eh_handler",
           &StreamerBase::emit_win_eh_handler,
           "state"_a, "sym"_a, "unwind"_a, "except_"_a, "loc"_a)
      .def("emit_win_eh_handler_data",
           &StreamerBase::emit_win_eh_handler_data,
           "state"_a, "loc"_a)
      .def("emit_cg_profile_entry",
           &StreamerBase::emit_cg_profile_entry,
           "state"_a, "from_"_a, "to"_a, "count"_a)
      .def("emit_syntax_directive",
           &StreamerBase::emit_syntax_directive,
           "state"_a)
#if NOT_IMPLEMENTED
      .def("emit_reloc_directive",
           &StreamerBase::emit_reloc_directive,
           "state"_a, "offset"_a, "name"_a, "expr"_a, "loc"_a, "sti"_a)
#endif
      .def("emit_addrsig",
           &StreamerBase::emit_addrsig,
           "state"_a)
      .def("emit_addrsig_sym",
           &StreamerBase::emit_addrsig_sym,
           "state"_a, "sym"_a)
#if NOT_IMPLEMENTED
      .def("emit_pseudo_probe",
           &StreamerBase::emit_pseudo_probe,
           "state"_a, "guid"_a, "index"_a, "type"_a, "attr"_a,
           "inline_stack"_a)
#endif
      .def("emit_bundle_align_mode",
           &StreamerBase::emit_bundle_align_mode,
           "state"_a, "align_pow_2"_a)
      .def("emit_bundle_lock",
           &StreamerBase::emit_bundle_lock,
           "state"_a, "align_to_end"_a)
      .def("emit_bundle_unlock",
           &StreamerBase::emit_bundle_unlock,
           "state"_a)
#if NOT_IMPLEMENTED
      .def("emit_dwarf_unit_length",
           &StreamerBase::emit_dwarf_unit_length,
           "state"_a, "length"_a, "comment"_a)
      .def("emit_dwarf_unit_length",
           &StreamerBase::emit_dwarf_unit_length,
           "state"_a, "prefix"_a, "comment"_a)
#endif
      .def("emit_dwarf_line_start_label",
           &StreamerBase::emit_dwarf_line_start_label,
           "state"_a, "start_sym"_a)
      .def("emit_dwarf_line_end_entry",
           &StreamerBase::emit_dwarf_line_end_entry,
           "state"_a, "section"_a, "last_label"_a)
      .def("emit_dwarf_advance_line_addr",
           &StreamerBase::emit_dwarf_advance_line_addr,
           "state"_a,"line_delta"_a,"last_label"_a, "label"_a,
           "pointer_size"_a)

      .def("emit_instruction",
           &StreamerBase::emit_instruction,
           "state"_a, "inst"_a, "bytes"_a, "fixups"_a)
      .def("diagnostic",
           &StreamerBase::diagnostic,
           "state"_a, "diag"_a);

  py::enum_<X86Syntax>(m, "X86Syntax")
      .value("ATT", X86Syntax::ATT)
      .value("INTEL", X86Syntax::INTEL);

  py::class_<Assembler>(m, "Assembler")
      .def(py::init<std::string>(),
           "triple"_a)
      .def("assemble",
           &Assembler::assemble,
           "streamer"_a, "asm"_a)
      .def_property("x86_syntax",
                    &Assembler::get_x86_syntax,
                    &Assembler::set_x86_syntax)
      .def_static("default_triple",
                  &Assembler::default_target);
  // clang-format on
}
