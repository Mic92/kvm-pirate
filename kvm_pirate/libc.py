#!/usr/bin/env python3

import ctypes
from typing import Tuple

libc = ctypes.CDLL(None, use_errno=True)


def errcheck(
    ret: int, func: "ctypes._FuncPointer", args: Tuple["ctypes._CData", ...]
) -> int:
    if ret == -1:
        raise OSError(ctypes.get_errno())
    return ret


libc.ptrace.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long
# don't know how to satisfy mypy here
libc.ptrace.errcheck = errcheck  # type: ignore


class iovec(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_size_t),
    ]


libc.process_vm_readv.errcheck = errcheck  # type: ignore
libc.process_vm_readv.argtypes = [
    ctypes.c_int,
    ctypes.POINTER(iovec),
    ctypes.c_ulong,
    ctypes.POINTER(iovec),
    ctypes.c_ulong,
    ctypes.c_ulong,
]
libc.ptrace.restype = ctypes.c_ssize_t
