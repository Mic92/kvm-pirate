#!/usr/bin/env python3

from os import uname
import sys
from sys import byteorder
from ctypes import sizeof, c_void_p, Structure, c_ushort, c_ulong, pointer
from typing import List, Tuple, Union, Type, Any, cast

CPU_BIGENDIAN = byteorder == "big"
CPU_64BITS = sizeof(c_void_p) == 8

if CPU_64BITS:
    CPU_WORD_SIZE = 8  # bytes
    CPU_MAX_UINT = 0xFFFFFFFFFFFFFFFF
else:
    CPU_WORD_SIZE = 4  # bytes
    CPU_MAX_UINT = 0xFFFFFFFF

# guess machine type using uname()
_machine = uname()[4]
CPU_PPC32 = _machine == "ppc"
CPU_PPC64 = _machine in ("ppc64", "ppc64le")
CPU_I386 = _machine in ("i386", "i686")  # compatible Intel 32 bits
CPU_X86_64 = _machine in ("x86_64", "amd64")  # compatible Intel 64 bits
CPU_ARM32 = _machine.startswith("arm")
CPU_AARCH64 = _machine == "aarch64"
del _machine

CPU_INTEL = CPU_I386 or CPU_X86_64
CPU_POWERPC = CPU_PPC32 or CPU_PPC64
CPU_ARM = CPU_ARM32 or CPU_AARCH64

CPU_INSTR_POINTER: str
CPU_STACK_POINTER: str
CPU_FRAME_POINTER: str

if CPU_POWERPC:
    CPU_INSTR_POINTER = "nip"
    CPU_STACK_POINTER = "gpr1"
    SYSCALL_NR = "r0"
    SYSCALL_RET = "r3"
    SYSCALL_ARGS = ["r3", "r4", "r5", "r6", "r7", "r8", "r9"]
elif CPU_ARM32:
    CPU_INSTR_POINTER = "r15"
    CPU_STACK_POINTER = "r14"
    CPU_FRAME_POINTER = "r11"
    SYSCALL_NR = "r7"
    SYSCALL_RET = "r0"
    SYSCALL_ARGS = ["r0", "r1", "r2", "r3", "r4", "r5", "r6"]
elif CPU_AARCH64:
    CPU_INSTR_POINTER = "pc"
    CPU_STACK_POINTER = "sp"
    CPU_FRAME_POINTER = "r29"
    SYSCALL_NR = "w8"
    SYSCALL_RET = "x0"
    SYSCALL_ARGS = ["x0", "x1", "x2", "x3", "x4", "x5"]
elif CPU_X86_64:
    CPU_INSTR_POINTER = "rip"
    CPU_STACK_POINTER = "rsp"
    CPU_FRAME_POINTER = "rbp"
    SYSCALL_NR = "rax"
    SYSCALL_RET = "rax"
    SYSCALL_ARGS = ["rdi", "rsi", "rdx", "r10", "r8", "r9"]
elif CPU_I386:
    CPU_INSTR_POINTER = "eip"
    CPU_STACK_POINTER = "esp"
    CPU_FRAME_POINTER = "ebp"
    SYSCALL_NR = "eax"
    SYSCALL_RET = "eax"
    SYSCALL_ARGS = ["ebx", "ecx", "edx", "esi", "edi", "ebp"]
else:
    print("Unsupported CPU architecture", file=sys.stderr)
    sys.exit(1)


if CPU_PPC32:
    registers: List[Tuple[str, Union[Type[c_ulong], Type[c_ushort]]]] = [
        ("gpr0", c_ulong),
        ("gpr1", c_ulong),
        ("gpr2", c_ulong),
        ("gpr3", c_ulong),
        ("gpr4", c_ulong),
        ("gpr5", c_ulong),
        ("gpr6", c_ulong),
        ("gpr7", c_ulong),
        ("gpr8", c_ulong),
        ("gpr9", c_ulong),
        ("gpr10", c_ulong),
        ("gpr11", c_ulong),
        ("gpr12", c_ulong),
        ("gpr13", c_ulong),
        ("gpr14", c_ulong),
        ("gpr15", c_ulong),
        ("gpr16", c_ulong),
        ("gpr17", c_ulong),
        ("gpr18", c_ulong),
        ("gpr19", c_ulong),
        ("gpr20", c_ulong),
        ("gpr21", c_ulong),
        ("gpr22", c_ulong),
        ("gpr23", c_ulong),
        ("gpr24", c_ulong),
        ("gpr25", c_ulong),
        ("gpr26", c_ulong),
        ("gpr27", c_ulong),
        ("gpr28", c_ulong),
        ("gpr29", c_ulong),
        ("gpr30", c_ulong),
        ("gpr31", c_ulong),
        ("nip", c_ulong),
        ("msr", c_ulong),
        ("orig_gpr3", c_ulong),
        ("ctr", c_ulong),
        ("link", c_ulong),
        ("xer", c_ulong),
        ("ccr", c_ulong),
        ("mq", c_ulong),  # FIXME: ppc64 => softe
        ("trap", c_ulong),
        ("dar", c_ulong),
        ("dsisr", c_ulong),
        ("result", c_ulong),
    ]
elif CPU_PPC64:
    registers = [
        ("gpr0", c_ulong),
        ("gpr1", c_ulong),
        ("gpr2", c_ulong),
        ("gpr3", c_ulong),
        ("gpr4", c_ulong),
        ("gpr5", c_ulong),
        ("gpr6", c_ulong),
        ("gpr7", c_ulong),
        ("gpr8", c_ulong),
        ("gpr9", c_ulong),
        ("gpr10", c_ulong),
        ("gpr11", c_ulong),
        ("gpr12", c_ulong),
        ("gpr13", c_ulong),
        ("gpr14", c_ulong),
        ("gpr15", c_ulong),
        ("gpr16", c_ulong),
        ("gpr17", c_ulong),
        ("gpr18", c_ulong),
        ("gpr19", c_ulong),
        ("gpr20", c_ulong),
        ("gpr21", c_ulong),
        ("gpr22", c_ulong),
        ("gpr23", c_ulong),
        ("gpr24", c_ulong),
        ("gpr25", c_ulong),
        ("gpr26", c_ulong),
        ("gpr27", c_ulong),
        ("gpr28", c_ulong),
        ("gpr29", c_ulong),
        ("gpr30", c_ulong),
        ("gpr31", c_ulong),
        ("nip", c_ulong),
        ("msr", c_ulong),
        ("orig_gpr3", c_ulong),
        ("ctr", c_ulong),
        ("link", c_ulong),
        ("xer", c_ulong),
        ("ccr", c_ulong),
        ("softe", c_ulong),
        ("trap", c_ulong),
        ("dar", c_ulong),
        ("dsisr", c_ulong),
        ("result", c_ulong),
    ]
elif CPU_ARM32:
    registers = list(("r%i" % reg, c_ulong) for reg in range(18))
elif CPU_AARCH64:
    registers = list(
        [
            *[("r%i" % reg, c_ulong) for reg in range(31)],
            ("sp", c_ulong),
            ("pc", c_ulong),
            ("pstate", c_ulong),
        ]
    )
elif CPU_64BITS:
    registers = [
        ("r15", c_ulong),
        ("r14", c_ulong),
        ("r13", c_ulong),
        ("r12", c_ulong),
        ("rbp", c_ulong),
        ("rbx", c_ulong),
        ("r11", c_ulong),
        ("r10", c_ulong),
        ("r9", c_ulong),
        ("r8", c_ulong),
        ("rax", c_ulong),
        ("rcx", c_ulong),
        ("rdx", c_ulong),
        ("rsi", c_ulong),
        ("rdi", c_ulong),
        ("orig_rax", c_ulong),
        ("rip", c_ulong),
        ("cs", c_ulong),
        ("eflags", c_ulong),
        ("rsp", c_ulong),
        ("ss", c_ulong),
        ("fs_base", c_ulong),
        ("gs_base", c_ulong),
        ("ds", c_ulong),
        ("es", c_ulong),
        ("fs", c_ulong),
        ("gs", c_ulong),
    ]
else:
    registers = [
        ("ebx", c_ulong),
        ("ecx", c_ulong),
        ("edx", c_ulong),
        ("esi", c_ulong),
        ("edi", c_ulong),
        ("ebp", c_ulong),
        ("eax", c_ulong),
        ("ds", c_ushort),
        ("__ds", c_ushort),
        ("es", c_ushort),
        ("__es", c_ushort),
        ("fs", c_ushort),
        ("__fs", c_ushort),
        ("gs", c_ushort),
        ("__gs", c_ushort),
        ("orig_eax", c_ulong),
        ("eip", c_ulong),
        ("cs", c_ushort),
        ("__cs", c_ushort),
        ("eflags", c_ulong),
        ("esp", c_ulong),
        ("ss", c_ushort),
        ("__ss", c_ushort),
    ]


# From /usr/include/asm-i386/user.h
# Also more reliably in the kernel sources:
# arch/$ARCH/include/uapi/asm/ptrace.h
class user_regs_struct(Structure):
    _fields_ = registers

    def __str__(self) -> str:
        regs = {}
        for reg in self.__class__._fields_:
            regs.update({reg[0]: getattr(self, reg[0])})
        return str(regs)

    def prepare_syscall(self, number: int, *args: Any) -> "user_regs_struct":
        regs = user_regs_struct()
        # copy current state to it
        pointer(regs)[0] = self
        setattr(regs, SYSCALL_NR, number)
        for i, arg in enumerate(args):
            setattr(regs, SYSCALL_ARGS[i], arg)
        return regs

    def syscall_result(self) -> int:
        return int(getattr(self, SYSCALL_RET))

    @property
    def sp(self) -> int:
        return int(getattr(self, CPU_STACK_POINTER))

    @sp.setter
    def sp(self, value: int) -> None:
        setattr(self, CPU_STACK_POINTER, value)

    @property
    def ip(self) -> int:
        return int(getattr(self, CPU_INSTR_POINTER))

    @ip.setter
    def ip(self, value: int) -> None:
        setattr(self, CPU_INSTR_POINTER, value)

    @property
    def fp(self) -> int:
        assert CPU_FRAME_POINTER is not None
        return int(getattr(self, CPU_FRAME_POINTER))

    @fp.setter
    def fp(self, value: int) -> None:
        setattr(self, CPU_INSTR_POINTER, value)
