import argparse
import inspect
import re
import sys
from types import NoneType
from typing import Any, Dict, List, Optional

import mcasm

try:
    import rich
    import rich.tree
except ImportError:
    print("Please install 'mcasm[cli]' to use this command.", file=sys.stderr)
    sys.exit(1)


class PrettyPrintingStreamer(mcasm.Streamer):
    def __init__(self):
        self._current_tree: Optional[rich.tree.Tree] = None
        self._argnames = self._extract_arg_names()
        super().__init__()

    def _parse_help_decl(self, method_help: str) -> Optional[List[str]]:
        """
        Parses a pybind11-generated docstr to extract parameter names.

        This is required because pybind11 methods are not compatible with
        inspect.Signature.
        """

        decl_re = re.compile(r"[a-zA-Z0-9_]+\((.*)\) -> .+")
        arg_re = re.compile(r"([a-zA-Z0-9_]+): [a-zA-Z0-9_.]+")

        for line in method_help.splitlines():
            match = decl_re.match(line)
            if match:
                return [
                    arg_match.group(1)
                    for arg_match in arg_re.finditer(match.group(1))
                ]

        return None

    def _extract_arg_names(self) -> Dict[str, List[str]]:
        """
        Generates a map from method name to their argument names.
        """

        result: Dict[str, List[str]] = {}

        for name in dir(self):
            if name[0] == "_" or name == "unhandled_event":
                continue

            attr = getattr(self, name)
            if not inspect.ismethod(attr) or not attr.__doc__:
                continue

            arg_names = self._parse_help_decl(attr.__doc__)
            if arg_names is not None:
                if arg_names and arg_names[0] == "self":
                    del arg_names[0]
                result[name] = arg_names

        return result

    def _is_enum_like(self, value: Any) -> bool:
        """
        Determines if a value looks like a pybind11 enum instance.
        """

        return (
            hasattr(value, "__members__")
            and hasattr(value, "value")
            and hasattr(value, "name")
        )

    def _add_value_node(
        self, parent: rich.tree.Tree, name: str, value: Any
    ) -> None:
        """
        Adds a named value to the tree, potentially creating additional child
        nodes.
        """

        if isinstance(value, (int, bool, str, float, bytes, NoneType)):
            parent.add(f"{name} = {value!r}")
            return

        if self._is_enum_like(value):
            parent.add(f"{name} = {type(value).__qualname__}.{value.name}")
            return

        if isinstance(value, list):
            if not value:
                parent.add(f"{name} = []")
                return

            node = parent.add(f"{name} [i](list)[/i]")
            for i, value in enumerate(value):
                self._add_value_node(node, f"[{i}]", value)
            return

        if isinstance(value, dict):
            if not value:
                parent.add(name + " = {}")
                return

            node = parent.add(f"{name} [i](dict)[/i]")
            for key, value in value.items():
                self._add_value_node(node, key, value)
            return

        # Assume all other types should be printed as a class with attributes
        node = parent.add(f"{name} [i]({type(value).__name__})[/i]")
        for name in sorted(dir(type(value))):
            if name[0] == "_":
                continue

            type_attr = getattr(type(value), name)
            if not isinstance(type_attr, property):
                continue

            self._add_value_node(node, name, getattr(value, name))

    def unhandled_event(self, name: str, base_impl, *args, **kwargs):
        def make_node(value: str) -> rich.tree.Tree:
            if self._current_tree:
                return self._current_tree.add(value)
            else:
                self._current_tree = rich.tree.Tree(value)
                return self._current_tree

        root = make_node(f"⚡️ [b]{name}[/b]")
        arg_names = self._argnames.get(name, [])
        for i, (arg_name, arg) in enumerate(zip(arg_names, args)):
            self._add_value_node(root, arg_name or f"[{i}]", arg)

        # Call into super here because this may trigger additional events to
        # fire and we want those to be nested in our tree.
        result = super().unhandled_event(name, base_impl, *args, **kwargs)

        if root == self._current_tree:
            rich.print(root)
            self._current_tree = None
            print()

        return result


class NameOnlyStreamer(mcasm.Streamer):
    def unhandled_event(self, name: str, base_impl, *args, **kwargs) -> Any:
        print(name)
        return super().unhandled_event(name, base_impl, *args, **kwargs)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="parse an assembly file and print out the mc-asm callbacks"
    )
    ap.add_argument(
        "asm", type=argparse.FileType("r"), help="the assembly file to parse"
    )
    ap.add_argument(
        "--target",
        default=mcasm.Assembler.default_triple(),
        help="the target triple to use (default: %(default)s)",
    )
    ap.add_argument(
        "--syntax",
        choices=["intel", "att"],
        default="intel",
        help="the syntax to use (default: %(default)s)",
    )
    ap.add_argument(
        "--names-only",
        action="store_true",
        help="only print the callback names instead of the detailed output",
    )
    args = ap.parse_args()

    if args.syntax == "intel":
        syntax = mcasm.X86Syntax.INTEL
    elif args.syntax == "att":
        syntax = mcasm.X86Syntax.ATT
    else:
        assert False, "invalid syntax name"

    with args.asm:
        asm = args.asm.read()

    assembler = mcasm.Assembler(args.target)
    assembler.x86_syntax = syntax

    if not assembler.assemble(
        NameOnlyStreamer() if args.names_only else PrettyPrintingStreamer(),
        asm,
    ):
        sys.exit(1)


if __name__ == "__main__":
    main()
