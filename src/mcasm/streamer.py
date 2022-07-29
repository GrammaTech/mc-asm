import functools
import inspect
import sys
import types
from typing import Any, Callable

from ._core import Streamer as _Streamer

# We want un-overridden methods to invoke unhandled_event on the streamer.
# This ended up being easiest to do from Python.
#
# Conceptually, all we do is look for unhandled overrides and add a new stub
# override that calls unhandled_event.


class Streamer(_Streamer):
    def __init__(self) -> None:
        self._add_unhandled_overrides()
        super().__init__()

    def _add_unhandled_overrides(self) -> None:
        """
        Adds overrides for all unhandled streamer callbacks. The overrides
        will call unhandled_event.
        """
        for name in dir(_Streamer):
            self_attr = getattr(self, name)
            base_attr = getattr(_Streamer, name)

            if (
                name[0] != "_"
                and inspect.ismethod(self_attr)
                and self_attr.__func__ == base_attr.__func__
            ):
                unhandled_impl = self._make_unhandled_impl(name, self_attr)
                setattr(self, name, unhandled_impl)

    def _make_unhandled_impl(self, name: str, base_impl: Callable) -> None:
        """
        Creates an override of a given method that calls unhandled_event,
        passing in the method name, superclass' method, and the received
        arguments.
        """

        invoker = self._make_super_invoker(name, base_impl)

        @functools.wraps(base_impl)
        def trampoline(self, *args, **kwargs):
            return self.unhandled_event(name, invoker, *args, **kwargs)

        return trampoline.__get__(self, Streamer)

    def _make_super_invoker(self, name: str, base_impl: Callable) -> Callable:
        """
        Creates a stub function that tricks pybind11 into thinking the call to
        `base_impl` is done through super().
        """

        @functools.wraps(base_impl)
        def invoker(self, *args, **kwargs):
            return base_impl(*args, **kwargs)

        # To figure out if we're invoking an override, pybind11 looks at
        # the frame's code's co_name and that self is correct. If it gets
        # this wrong, it'll result in a stack overflow.
        if sys.version_info >= (3, 8):
            invoker.__code__ = invoker.__code__.replace(co_name=name)
        else:
            invoker.__code__ = types.CodeType(
                invoker.__code__.co_argcount,
                invoker.__code__.co_kwonlyargcount,
                invoker.__code__.co_nlocals,
                invoker.__code__.co_stacksize,
                invoker.__code__.co_flags,
                invoker.__code__.co_code,
                invoker.__code__.co_consts,
                invoker.__code__.co_names,
                invoker.__code__.co_varnames,
                invoker.__code__.co_filename,
                name,  # co_name
                invoker.__code__.co_firstlineno,
                invoker.__code__.co_lnotab,
                invoker.__code__.co_freevars,
                invoker.__code__.co_cellvars,
            )

        return invoker.__get__(self, Streamer)

    def unhandled_event(
        self, name: str, base_impl: Callable, *args, **kwargs
    ) -> Any:
        return base_impl(*args, **kwargs)
