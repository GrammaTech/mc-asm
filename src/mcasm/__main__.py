import argparse
import inspect
import re
import sys
from typing import Any, Callable, Dict, List, Optional

import mcasm

try:
    import rich
    import rich.tree
except ImportError:
    print("Please install 'mcasm[cli]' to use this command.", file=sys.stderr)
    sys.exit(1)

# types.NoneType is too new to rely on, so just declare it here.
NoneType = type(None)

FilterFunc = Callable[[str, mcasm.ParserState], bool]


class PrettyPrintingStreamer(mcasm.Streamer):
    def __init__(self, filter_func: FilterFunc, verbose: bool):
        self._current_tree: Optional[rich.tree.Tree] = None
        self._argnames = self._extract_arg_names()
        self._filter_func = filter_func
        self._verbose = verbose
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

    def _is_default_value(self, value: Any) -> bool:
        """
        Is this value the default value for the type?
        """
        if value is None:
            return True

        if isinstance(value, (int, bool, str, float, bytes, list, dict, set)):
            return value == type(value)()

        return False

    def _add_value_node(
        self,
        parent: rich.tree.Tree,
        name: str,
        value: Any,
        force_print: bool = False,
    ) -> None:
        """
        Adds a named value to the tree, potentially creating additional child
        nodes.
        """

        if (
            not self._verbose
            and not force_print
            and self._is_default_value(value)
        ):
            return

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
                self._add_value_node(node, f"[{i}]", value, force_print=True)
            return

        if isinstance(value, dict):
            if not value:
                parent.add(name + " = {}")
                return

            node = parent.add(f"{name} [i](dict)[/i]")
            for key, value in value.items():
                self._add_value_node(node, key, value, force_print=True)
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
        if not self._filter_func(name, args[0]):
            return super().unhandled_event(name, base_impl, *args, **kwargs)

        def make_node(value: str) -> rich.tree.Tree:
            if self._current_tree:
                return self._current_tree.add(value)
            else:
                self._current_tree = rich.tree.Tree(value)
                return self._current_tree

        root = make_node(f"⚡️ [b]{name}[/b]")
        arg_names = self._argnames.get(name, [])
        for i, (arg_name, arg) in enumerate(zip(arg_names, args)):
            self._add_value_node(
                root, arg_name or f"[{i}]", arg, force_print=True
            )

        # Call into super here because this may trigger additional events to
        # fire and we want those to be nested in our tree.
        result = super().unhandled_event(name, base_impl, *args, **kwargs)

        if root == self._current_tree:
            rich.print(root)
            self._current_tree = None
            print()

        return result


class NameOnlyStreamer(mcasm.Streamer):
    def __init__(self, filter_func: FilterFunc):
        self._filter_func = filter_func
        super().__init__()

    def unhandled_event(self, name: str, base_impl, *args, **kwargs) -> Any:
        if self._filter_func(name, args[0]):
            print(name)

        return super().unhandled_event(name, base_impl, *args, **kwargs)


def make_line_filter(start: int, end: Optional[int]) -> FilterFunc:
    """
    Creates a filter function that matches line numbers.
    """

    def line_filter(event_name: str, state: mcasm.ParserState) -> bool:
        if end is not None:
            return start >= state.loc.lineno >= end
        else:
            return start == state.loc.lineno

    return line_filter


def make_event_filter(name: str) -> FilterFunc:
    """
    Creates a filter function that matches event names.
    """

    def event_filter(event_name: str, state: mcasm.ParserState) -> bool:
        return event_name == name

    return event_filter


def filter_type(value: str) -> FilterFunc:
    """
    An argparse type that accepts filters (event names or line numbers).
    """
    lineno_re = re.compile("([0-9]+)(?:-([0-9]+))")
    name_re = re.compile("([a-z][a-zA-Z0-9_]+)")

    match = lineno_re.match(value)
    if match:
        start = int(match.group(1))
        end = int(match.group(2)) if match.group(2) is not None else None
        return make_line_filter(start, end)

    match = name_re.match(value)
    if match:
        return make_event_filter(match.group(1))

    raise argparse.ArgumentTypeError("unknown filter type")


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
    ap.add_argument(
        "--filter",
        action="append",
        type=filter_type,
        help="only print out callbacks with a given name or line number",
    )
    ap.add_argument(
        "--verbose", action="store_true", help="print out all object values"
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

    def filter_func(event_name: str, state: mcasm.ParserState) -> bool:
        if not args.filter:
            return True

        return any(f(event_name, state) for f in args.filter)

    if args.names_only:
        streamer = NameOnlyStreamer(filter_func)
    else:
        streamer = PrettyPrintingStreamer(filter_func, args.verbose)

    if not assembler.assemble(streamer, asm):
        sys.exit(1)


if __name__ == "__main__":
    main()
