#!/usr/bin/env python3

import os
import signal
import ctypes
from contextlib import contextmanager
from typing import Any, Generator

from . import cpu, ptrace
from .syscalls import SYSCALL_TEXT, SYSCALL_NAMES


class SyscallError(OSError):
    pass


class ExitError(SyscallError):
    pass


class Process:
    def __init__(self, pid: int, saved_regs: cpu.user_regs_struct) -> None:
        self.pid = pid
        self.saved_regs = saved_regs

    def syscall(self, *args: Any) -> int:
        regs = self.saved_regs.prepare_syscall(*args)
        ptrace.setregs(self.pid, regs)
        # FIXME: on arm we would need PTRACE_SET_SYSCALL
        ptrace.syscall(self.pid)
        _, status = os.waitpid(self.pid, 0)
        if os.WIFSTOPPED(status) and os.WEXITSTATUS(status) & ~0x80 == signal.SIGTRAP:
            ptrace.syscall(self.pid)
            _, status = os.waitpid(self.pid, 0)

        if os.WIFSTOPPED(status):
            result = ptrace.getregs(self.pid)
            assert self.saved_regs.ip == result.ip - 2, f"{self.saved_regs.ip} != {result.ip - 2}"
            ptrace.setregs(self.pid, self.saved_regs)
            return result.syscall_result()

        if os.WIFEXITED(status):
            exit_code = os.WEXITSTATUS(status)
            raise ExitError(f"process exited with: {exit_code}")
        elif os.WIFSIGNALED(status):
            sigcode = os.WTERMSIG(status)
            raise ExitError(
                f"process stopped by signal: {sigcode} ({signal.strsignal(sigcode)})"
            )
        else:
            raise SyscallError("failed to invoke syscall")

    def ioctl(self, fd: int, request: int, arg: Any = 0) -> int:
        return ctypes.c_int(self.syscall(SYSCALL_NAMES["ioctl"], fd, request, arg)).value


@contextmanager
def save_regs(pid: int) -> Generator[cpu.user_regs_struct, None, None]:
    old_regs = ptrace.getregs(pid)
    assert old_regs.ip != 0
    try:
        yield old_regs
    finally:
        ptrace.setregs(pid, old_regs)


@contextmanager
def save_text(pid: int, ip: int) -> Generator[int, None, None]:
    old_text = ptrace.peektext(pid, ip)
    try:
        yield old_text
    finally:
        ptrace.poketext(pid, ip, old_text)


@contextmanager
def attach(pid: int) -> Generator[Process, None, None]:
    threads = []

    try:
        for thread in os.listdir(f"/proc/{pid}/task"):
            tid = int(thread)
            ptrace.attach(tid)
            _, status = os.waitpid(tid, 0)
            assert os.WIFSTOPPED(status), "Could attach to pid"
            threads.append(tid)

        with save_regs(pid) as regs:
            with save_text(pid, regs.ip):
                ptrace.poketext(pid, regs.ip, SYSCALL_TEXT)
                yield Process(pid, regs)
    finally:
        for tid in threads:
            ptrace.detach(tid)
