import argparse
from pprint import pprint

from .assembler import Assembler, X86Syntax


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("asm", type=argparse.FileType("r"))
    ap.add_argument("--target", default=Assembler.default_target())
    ap.add_argument("--syntax", choices=["intel", "att"], default="intel")
    args = ap.parse_args()

    if args.syntax == "intel":
        syntax = X86Syntax.INTEL
    elif args.syntax == "att":
        syntax = X86Syntax.ATT
    else:
        assert False, "invalid syntax name"

    with args.asm:
        asm = args.asm.read()

    assembler = Assembler(args.target)
    assembler.x86_syntax = syntax

    for event in assembler.assemble(asm):
        pprint(event)


if __name__ == "__main__":
    main()
