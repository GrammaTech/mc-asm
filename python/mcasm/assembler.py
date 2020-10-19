import ctypes
import enum
import json
import typing

import pkg_resources

_LIB = ctypes.cdll.LoadLibrary(
    pkg_resources.resource_filename("mcasm", "libmcasm.so")
)

_LIB.MCAssemblerCreate.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_void_p),
]
_LIB.MCAssemblerCreate.restype = ctypes.c_int

_LIB.MCAssemblerAssembleToJSON.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_char_p),
]
_LIB.MCAssemblerAssembleToJSON.restype = ctypes.c_int

_LIB.MCAssemblerSetOption.argtypes = [
    ctypes.c_void_p,
    ctypes.c_int,
    ctypes.c_size_t,
]
_LIB.MCAssemblerSetOption.restype = ctypes.c_int

_LIB.MCAssemblerDestroy.argtypes = [ctypes.c_void_p]
_LIB.MCAssemblerDestroy.restype = None

_LIB.MCDefaultTriple.argtypes = []
_LIB.MCDefaultTriple.restype = ctypes.c_char_p

_LIB.MCErrorToString.argtypes = [ctypes.c_int]
_LIB.MCErrorToString.restype = ctypes.c_char_p

_MC_OPTION_X86_SYNTAX = 0
_MC_X86_SYNTAX_ATT = 0
_MC_X86_SYNTAX_INTEL = 1

_MC_ERROR_SUCCESS = 0
_MC_ERROR_FAILED_WITH_DIAGNOSTICS = 1


class X86Syntax(enum.IntEnum):
    ATT = _MC_X86_SYNTAX_ATT
    INTEL = _MC_X86_SYNTAX_INTEL


class AsmSyntaxError(Exception):
    def __init__(self, lineno: int, column: int, message: str):
        super().__init__(message)
        self.lineno = lineno
        self.column = column


class Assembler:
    def __init__(self, target: str) -> None:
        self._parser = ctypes.c_void_p()
        err = _LIB.MCAssemblerCreate(
            target.encode(), ctypes.byref(self._parser)
        )
        if err != _MC_ERROR_SUCCESS:
            raise RuntimeError(self._error_string(err))
        self.x86_syntax = X86Syntax.ATT

    def __del__(self) -> None:
        _LIB.MCAssemblerDestroy(self._parser)

    @property
    def x86_syntax(self) -> X86Syntax:
        return self._x86_syntax

    @x86_syntax.setter
    def x86_syntax(self, value: X86Syntax) -> None:
        err = _LIB.MCAssemblerSetOption(
            self._parser, _MC_OPTION_X86_SYNTAX, value
        )
        if err != _MC_ERROR_SUCCESS:
            raise RuntimeError(self._error_string(err))
        self._x86_syntax = value

    def assemble(self, asm: str) -> typing.List[dict]:
        """
        Assembles an assemble string into a series of events.
        :param asm: The assembly string.
        :returns: A list of events, where each event is a dict with a "kind"
                  key that is the type of the event.
        """
        data = ctypes.c_char_p()
        err = _LIB.MCAssemblerAssembleToJSON(
            self._parser, asm.encode(), ctypes.byref(data)
        )
        if err not in [_MC_ERROR_SUCCESS, _MC_ERROR_FAILED_WITH_DIAGNOSTICS]:
            raise RuntimeError(self._error_string(err))

        events = json.loads(data.value.decode())

        if err == _MC_ERROR_FAILED_WITH_DIAGNOSTICS:
            # Find the first error diagnostic and create an exception for it
            diag = next(
                event
                for event in events
                if event["kind"] == "diagnostic"
                and event["diagnostic"]["kind"] == "error"
            )
            raise AsmSyntaxError(
                diag["diagnostic"]["line"],
                diag["diagnostic"]["column"],
                diag["diagnostic"]["message"],
            )

        return events

    @staticmethod
    def _error_string(err: int) -> str:
        return _LIB.MCErrorToString(err).decode()

    @staticmethod
    def default_target() -> str:
        """
        Returns the target triple for the current platform.
        """
        result = _LIB.MCDefaultTriple()
        return result.decode()
