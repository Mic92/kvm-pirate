#!/usr/bin/env python3
from .. import cpu

# SYSCALL_TEXT was generated with radare2's rasm2

if cpu.CPU_POWERPC:
    # FIXME requires multiple machine words
    raise Exception("system call not implemented yet")
    from .powerpc import SYSCALL_NAMES
elif cpu.CPU_ARM32:
    # what about thumb mode?
    # $ rasm2  -a arm -b 32 'svc 0'
    SYSCALL_TEXT = 0x000000ef
    from .arm import SYSCALL_NAMES
elif cpu.CPU_AARCH64:
    # $ rasm2  -a arm -b 64 'svc 0'
    SYSCALL_TEXT = 0x010000d4
    from .arm64 import SYSCALL_NAMES
elif cpu.CPU_X86_64:
    from .x86_64 import SYSCALL_NAMES
    # $ rasm2  -a x86 -b 64 'syscall'
    SYSCALL_TEXT = 0x050f
elif cpu.CPU_I386:
    # $ rasm2  -a x86 -b 32 'int 80'
    from .i386 import SYSCALL_NAMES
    SYSCALL_TEXT = 0x50cd
