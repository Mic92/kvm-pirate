#!/usr/bin/env python3

import ctypes
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.argtypes = [
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.c_void_p
]
libc.ptrace.restype = ctypes.c_long
