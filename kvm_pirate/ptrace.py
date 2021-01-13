from typing import Optional, Any
from .libc import libc
import ctypes
from .cpu import user_regs_struct

PTRACE_TRACEME = 0

PTRACE_PEEKTEXT = 1
PTRACE_POKETEXT = 4
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_SYSCALL = 24

PTRACE_SETOPTIONS = 16896
PTRACE_CONT = 7
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_O_TRACEEXIT = 0x00000040
PTRACE_O_TRACESYSGOOD = 0x00000001


def request(request: int, pid: int, addr: int, data: Any) -> int:
    res = libc.ptrace(request, pid, addr, data)
    assert res != 1
    return int(res)


def peektext(pid: int, ip: int) -> int:
    return request(PTRACE_PEEKTEXT, pid, ip, None)


def poketext(pid: int, ip: int, val: int) -> None:
    request(PTRACE_POKETEXT, pid, ip, val)


def getregs(pid: int) -> user_regs_struct:
    regs = user_regs_struct()
    request(PTRACE_GETREGS, pid, 0, ctypes.byref(regs))
    return regs


def setregs(pid: int, regs: user_regs_struct) -> None:
    request(PTRACE_SETREGS, pid, 0, ctypes.byref(regs))


def syscall(pid: int) -> None:
    request(PTRACE_SYSCALL, pid, 0, 0)


def singlestep(pid: int) -> None:
    request(PTRACE_SINGLESTEP, pid, 0, 0)


def me() -> None:
    request(PTRACE_TRACEME, 0, 0, 0)


def attach(pid: int) -> None:
    request(PTRACE_ATTACH, pid, 0, 0)


def cont(pid: int) -> None:
    request(PTRACE_CONT, pid, 0, 0)


def detach(pid: int) -> None:
    request(PTRACE_DETACH, pid, 0, 0)


def traceexit(pid: int) -> None:
    request(
        PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXIT
    )
