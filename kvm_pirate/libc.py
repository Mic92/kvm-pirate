#!/usr/bin/env python3

import ctypes
from typing import Any, Type, Tuple

libc = ctypes.CDLL(None, use_errno=True)


def errcheck(
    ret: "ctypes._CData", func: "ctypes._FuncPointer", args: Tuple["ctypes._CData", ...]
) -> "ctypes._CData":
    err = ctypes.get_errno()
    if err == 0:
        return ret
    raise OSError(err)


libc.ptrace.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long
# don't know how to satisfy mypy here
libc.ptrace.errcheck = errcheck  # type: ignore
