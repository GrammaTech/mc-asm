import unittest

from mcasm import AsmSyntaxError, Assembler, X86Syntax


class TestAssembler(unittest.TestCase):
    def test_instruction(self):
        asm = Assembler("x86_64-linux-gnu")
        events = asm.assemble("ud2")
        assert len(events) == 2
        assert events[0]["kind"] == "changeSection"
        assert events[0]["section"]["name"] == ".text"
        assert events[1]["kind"] == "instruction"
        assert events[1]["data"] == "0f0b"

    def test_data(self):
        asm = Assembler("x86_64-linux-gnu")
        events = asm.assemble(".byte 10")
        assert len(events) == 2
        assert events[0]["kind"] == "changeSection"
        assert events[0]["section"]["name"] == ".text"
        assert events[1]["kind"] == "bytes"
        assert events[1]["data"] == "0a"

    def test_invalid_asm(self):
        asm = Assembler("x86_64-linux-gnu")
        try:
            asm.assemble("xyzzy")
            assert False
        except AsmSyntaxError as err:
            assert err.lineno == 1
            assert err.column == 0

    def test_intel_syntax(self):
        asm = Assembler("x86_64-linux-gnu")
        asm.x86_syntax = X86Syntax.INTEL
        events = asm.assemble("mov ebp, esp")
        assert len(events) == 2
        assert events[0]["kind"] == "changeSection"
        assert events[0]["section"]["name"] == ".text"
        assert events[1]["kind"] == "instruction"
        assert events[1]["data"] == "89e5"

    def test_att_syntax(self):
        asm = Assembler("x86_64-linux-gnu")
        asm.x86_syntax = X86Syntax.ATT
        events = asm.assemble("mov %esp, %ebp")
        assert len(events) == 2
        assert events[0]["kind"] == "changeSection"
        assert events[0]["section"]["name"] == ".text"
        assert events[1]["kind"] == "instruction"
        assert events[1]["data"] == "89e5"

    def test_default_syntax(self):
        asm = Assembler("x86_64-linux-gnu")
        assert asm.x86_syntax == X86Syntax.ATT
        events = asm.assemble("mov %esp, %ebp")
        assert len(events) == 2
        assert events[0]["kind"] == "changeSection"
        assert events[0]["section"]["name"] == ".text"
        assert events[1]["kind"] == "instruction"
        assert events[1]["data"] == "89e5"

    def test_invalid_triple(self):
        try:
            Assembler("blah-blah-blah")
            assert False
        except RuntimeError:
            pass
