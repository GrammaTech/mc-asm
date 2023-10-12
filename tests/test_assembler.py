import textwrap
from unittest.mock import Mock

import mcasm
import pytest
from mcasm._core import ParserState


class MockAdaptor(mcasm.Streamer):
    """
    A Streamer subclass that sends all of the callbacks to a Mock object.

    This is required because pybind11 needs actual objects of the right class
    instead of mocks.
    """

    def __init__(self, mock):
        self._mock = mock
        super().__init__()

    def unhandled_event(self, name, base_impl, *args, **kwargs):
        mock_fn = getattr(self._mock, name)
        mock_ret = mock_fn(*args, **kwargs)
        if not isinstance(mock_ret, Mock):
            return mock_ret

        return super().unhandled_event(name, base_impl, *args, **kwargs)


@pytest.mark.parametrize(
    ("syntax", "src"),
    (
        (mcasm.X86Syntax.ATT, "mov %esp, %ebp"),
        (mcasm.X86Syntax.INTEL, "mov ebp, esp"),
    ),
)
def test_instruction(syntax: mcasm.X86Syntax, src: str):
    asm = mcasm.Assembler("x86_64-linux-gnu")
    assert asm.x86_syntax == mcasm.X86Syntax.ATT
    asm.x86_syntax = syntax
    streamer = Mock(spec=mcasm.Streamer)
    assert asm.assemble(MockAdaptor(streamer), src)

    all_calls = [call[0] for call in streamer.mock_calls]
    assert all_calls == [
        "init_sections",
        "change_section",
        "emit_instruction",
    ]

    assert streamer.change_section.called_once()
    state, section, subsection = streamer.change_section.call_args[0]
    assert isinstance(section, mcasm.mc.SectionELF)
    assert section.name == ".text"
    assert subsection is None

    assert streamer.emit_instruction.called_once()
    state, inst, bytes, fixups = streamer.emit_instruction.call_args[0]
    assert bytes == b"\x89\xE5"
    assert inst.desc.is_move_reg
    assert fixups == []


def test_data():
    asm = mcasm.Assembler("x86_64-linux-gnu")
    streamer = Mock(spec=mcasm.Streamer)
    assert asm.assemble(MockAdaptor(streamer), ".data\n.byte 42")

    all_calls = [call[0] for call in streamer.mock_calls]
    assert all_calls == [
        "init_sections",
        "change_section",
        "change_section",
        "emit_int_value",
        "emit_bytes",
    ]

    assert streamer.change_section.call_count == 2

    state, section, subsection = streamer.change_section.call_args_list[0][0]
    assert isinstance(section, mcasm.mc.SectionELF)
    assert section.name == ".text"
    assert subsection is None

    state, section, subsection = streamer.change_section.call_args_list[1][0]
    assert isinstance(section, mcasm.mc.SectionELF)
    assert section.name == ".data"
    assert subsection is None

    assert streamer.emit_int_value.called_once()
    state, value, size = streamer.emit_int_value.call_args[0]
    assert value == 42
    assert size == 1

    assert streamer.emit_bytes.called_once()
    state, bytes = streamer.emit_bytes.call_args[0]
    assert bytes == b"*"


def test_anon_symbol():
    asm = mcasm.Assembler("x86_64-linux-gnu")
    streamer = Mock(spec=mcasm.Streamer)
    assert asm.assemble(MockAdaptor(streamer), "x=.")

    all_calls = [call[0] for call in streamer.mock_calls]
    assert all_calls == [
        "init_sections",
        "change_section",
        "emit_label",
        "emit_assignment",
    ]

    assert streamer.emit_label.called_once()
    state, label_symbol, loc = streamer.emit_label.call_args[0]
    assert label_symbol.name
    assert label_symbol.is_temporary

    assert streamer.emit_assignment.called_once()
    state, assignment_symbol, value = streamer.emit_assignment.call_args[0]
    assert assignment_symbol.name == "x"
    assert isinstance(value, mcasm.mc.SymbolRefExpr)
    assert value.symbol.name == label_symbol.name


def test_explicit_cfi_directives():
    """
    Test that explicit CFI procedures trigger the correct callbacks.
    """
    asm = mcasm.Assembler("x86_64-linux-gnu")
    streamer = Mock(spec=mcasm.Streamer)
    asm.implicit_cfi_procedure = False
    assert asm.assemble(
        MockAdaptor(streamer),
        """
        .cfi_startproc
        .cfi_undefined 15
        .cfi_endproc
        """,
    )

    all_calls = [call[0] for call in streamer.mock_calls]
    assert all_calls == [
        "init_sections",
        "change_section",
        "emit_cfi_start_proc_impl",
        "emit_cfi_undefined",
        "emit_cfi_end_proc_impl",
    ]

    assert streamer.emit_cfi_start_proc_impl.called_once()
    assert streamer.emit_cfi_undefined.called_once()
    state, register = streamer.emit_cfi_undefined.call_args[0]
    assert register == 15
    assert streamer.emit_cfi_end_proc_impl.called_once()


def test_implicit_cfi_directives():
    """
    Test that implicit CFI procedures trigger the correct callbacks.
    """
    asm = mcasm.Assembler("x86_64-linux-gnu")
    streamer = Mock(spec=mcasm.Streamer)
    asm.implicit_cfi_procedure = True
    assert asm.assemble(MockAdaptor(streamer), ".cfi_undefined 15")

    all_calls = [call[0] for call in streamer.mock_calls]
    assert all_calls == [
        "init_sections",
        "change_section",
        "emit_cfi_start_proc_impl",
        "emit_cfi_undefined",
        "emit_cfi_end_proc_impl",
    ]

    assert streamer.emit_cfi_start_proc_impl.called_once()
    assert streamer.emit_cfi_undefined.called_once()
    state, register = streamer.emit_cfi_undefined.call_args[0]
    assert register == 15
    assert streamer.emit_cfi_end_proc_impl.called_once()


def test_implicit_cfi_directives_loc():
    """
    Test that implicit CFI procedures have no source location associated.
    """

    class Streamer(mcasm.Streamer):
        def emit_cfi_start_proc_impl(
            self, state: ParserState, cur_frame: mcasm.mc.DwarfFrameInfo
        ) -> None:
            assert state.loc is None
            super().emit_cfi_start_proc_impl(state, cur_frame)

        def emit_cfi_end_proc_impl(
            self, state: ParserState, cur_frame: mcasm.mc.DwarfFrameInfo
        ) -> None:
            assert state.loc is None
            super().emit_cfi_end_proc_impl(state, cur_frame)

    asm = mcasm.Assembler("x86_64-linux-gnu")
    asm.implicit_cfi_procedure = True
    assert asm.assemble(Streamer(), ".cfi_undefined 15")


def test_explicit_cfi_directives_loc():
    """
    Test that explicit CFI procedures have correct source locations.
    """

    class Streamer(mcasm.Streamer):
        def emit_cfi_start_proc_impl(
            self, state: ParserState, cur_frame: mcasm.mc.DwarfFrameInfo
        ) -> None:
            assert state.loc is not None
            assert state.loc.lineno == 1
            super().emit_cfi_start_proc_impl(state, cur_frame)

        def emit_cfi_end_proc_impl(
            self, state: ParserState, cur_frame: mcasm.mc.DwarfFrameInfo
        ) -> None:
            assert state.loc is not None
            assert state.loc.lineno == 3
            super().emit_cfi_end_proc_impl(state, cur_frame)

    asm = mcasm.Assembler("x86_64-linux-gnu")
    asm.implicit_cfi_procedure = False
    assert asm.assemble(
        Streamer(),
        textwrap.dedent(
            """\
            .cfi_startproc
            .cfi_undefined 15
            .cfi_endproc
            """
        ),
    )


def test_parse_error():
    asm = mcasm.Assembler("x86_64-linux-gnu")
    streamer = Mock(spec=mcasm.Streamer)
    assert not asm.assemble(MockAdaptor(streamer), "xyzzy")

    all_calls = [call[0] for call in streamer.mock_calls]
    assert all_calls == [
        "init_sections",
        "change_section",
        "diagnostic",
    ]

    assert streamer.diagnostic.called_once()
    state, diag = streamer.diagnostic.call_args[0]
    assert diag.kind == mcasm.mc.Diagnostic.Kind.Error
    assert diag.lineno == 1
    assert diag.offset == 0
    assert diag.message == "invalid instruction mnemonic 'xyzzy'"
    assert diag.text == "xyzzy"


def test_context_error():
    # Sometimes the MCContext's diagnostic handler is called instead of the
    # source manager's. Make sure we correctly catch this too.
    asm = mcasm.Assembler("x86_64-linux-gnu")
    streamer = Mock(spec=mcasm.Streamer)
    asm.assemble(MockAdaptor(streamer), ".cfi_endproc")

    all_calls = [call[0] for call in streamer.mock_calls]
    assert all_calls == [
        "init_sections",
        "change_section",
        "diagnostic",
    ]

    assert streamer.diagnostic.called_once()
    state, diag = streamer.diagnostic.call_args[0]
    assert diag.kind == mcasm.mc.Diagnostic.Kind.Error
    assert diag.lineno == 1
    assert diag.offset == 0
    assert diag.message == (
        "this directive must appear between .cfi_startproc and .cfi_endproc "
        "directives"
    )
    assert diag.text == ".cfi_endproc"


def test_invalid_triple():
    with pytest.raises(ValueError):
        mcasm.Assembler("blah-blah-blah")


def test_python_exceptions():
    asm = mcasm.Assembler("x86_64-linux-gnu")
    streamer = Mock(spec=mcasm.Streamer)
    streamer.change_section = Mock(side_effect=AssertionError())
    with pytest.raises(AssertionError):
        asm.assemble(MockAdaptor(streamer), "ud2")

    all_calls = [call[0] for call in streamer.mock_calls]
    assert all_calls == [
        "init_sections",
        "change_section",
        # emit_instruction should not be called due to the raised exception
    ]
