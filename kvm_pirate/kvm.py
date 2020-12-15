#!/usr/bin/env python3

import os
import re
import ctypes
import fcntl
from itertools import chain
from typing import IO, Any, Optional, List, Dict

from . import pidfd


GET_API_VERSION = 0xAE00
CREATE_VM = 0xAE01
SET_USER_MEMORY_REGION = 0x4020AE46
CREATE_VCPU = 0xAE41
GET_SREGS = 0x8138AE83
SET_SREGS = 0x4138AE84
NR_INTERRUPTS = 0x100
GET_VCPU_MMAP_SIZE = 0xAE04
GET_REGS = 0x8090AE81
SET_REGS = 0x4090AE82
GET_VCPU_MMAP_SIZE = 0xAE04
RUN = 0xAE80
EXIT_IO = 0x2
EXIT_SHUTDOWN = 0x8
SET_TSS_ADDR = 0xAE47
CREATE_IRQCHIP = 0xAE60
SET_IDENTITY_MAP_ADDR = 0x4008AE48
CREATE_PIT2 = 0x4040AE77
EXIT_IO_IN = 0x0
EXIT_IO_OUT = 0x1
GET_SUPPORTED_CPUID = 0xC008AE05
CPUID_SIGNATURE = 0x40000000
CPUID_FEATURES = 0x40000001
SET_CPUID2 = 0x4008AE90


class GuestError(Exception):
    pass


class Segment(ctypes.Structure):
    _fields_ = [
        ("base", ctypes.c_uint64),
        ("limit", ctypes.c_uint32),
        ("selector", ctypes.c_uint16),
        ("type", ctypes.c_uint8),
        ("present", ctypes.c_uint8),
        ("dpl", ctypes.c_uint8),
        ("db", ctypes.c_uint8),
        ("s", ctypes.c_uint8),
        ("l", ctypes.c_uint8),
        ("g", ctypes.c_uint8),
        ("avl", ctypes.c_uint8),
        ("unusable", ctypes.c_uint8),
        ("padding", ctypes.c_uint8),
    ]


class DTable(ctypes.Structure):
    _fields_ = [
        ("base", ctypes.c_uint64),
        ("limit", ctypes.c_uint16),
        ("padding", ctypes.c_uint16 * 3),
    ]


class Sregs(ctypes.Structure):
    _fields_ = [
        ("cs", Segment),
        ("ds", Segment),
        ("es", Segment),
        ("fs", Segment),
        ("gs", Segment),
        ("ss", Segment),
        ("tr", Segment),
        ("ldt", Segment),
        ("gdt", DTable),
        ("idt", DTable),
        ("cr0", ctypes.c_uint64),
        ("cr2", ctypes.c_uint64),
        ("cr3", ctypes.c_uint64),
        ("cr4", ctypes.c_uint64),
        ("cr8", ctypes.c_uint64),
        ("efer", ctypes.c_uint64),
        ("apic_base", ctypes.c_uint64),
        ("interrupt_bitmap", ctypes.c_uint64 * int((NR_INTERRUPTS + 63) / 64)),
    ]


class Regs(ctypes.Structure):
    _fields_ = [
        ("rax", ctypes.c_uint64),
        ("rbx", ctypes.c_uint64),
        ("rcx", ctypes.c_uint64),
        ("rdx", ctypes.c_uint64),
        ("rsi", ctypes.c_uint64),
        ("rdi", ctypes.c_uint64),
        ("rsp", ctypes.c_uint64),
        ("rbp", ctypes.c_uint64),
        ("r8", ctypes.c_uint64),
        ("r9", ctypes.c_uint64),
        ("r10", ctypes.c_uint64),
        ("r11", ctypes.c_uint64),
        ("r12", ctypes.c_uint64),
        ("r13", ctypes.c_uint64),
        ("r14", ctypes.c_uint64),
        ("r15", ctypes.c_uint64),
        ("rip", ctypes.c_uint64),
        ("rflags", ctypes.c_uint64),
    ]


class Guest:
    def __init__(self, vm_fd: IO[Any], vcpu_fds: List[IO[Any]]) -> None:
        self.vm_fd = vm_fd
        self.vcpus_fds = vcpu_fds

    def cpu_count(self) -> int:
        return len(self.vcpus_fds)

    def _vm_ioctl(self, request: int, arg: int = 0) -> None:
        fcntl.ioctl(self.vm_fd.fileno(), request, arg)

    def _cpu_ioctl(self, cpu: int, request: int, arg: Any = 0) -> None:
        fcntl.ioctl(self.vcpus_fds[cpu].fileno(), request, arg)

    def get_regs(self, cpu: int) -> Regs:
        regs = Regs()
        try:
            self._cpu_ioctl(cpu, GET_REGS, regs)
            return regs
        except OSError as err:
            raise GuestError("Failed to get special registers") from err

    def get_sregs(self, cpu: int) -> Sregs:
        sregs = Sregs()
        try:
            self._cpu_ioctl(cpu, GET_SREGS, sregs)
            return sregs
        except OSError as err:
            raise GuestError("Failed to get special registers") from err

    def exit(self):
        self.vm_fd.close()
        for fd in self.cpu_fds:
            fd.close()


def _find_vm_fd(
    entry: os.DirEntry,
    pid_fd: pidfd.PidFile,
    vm_fds: List[IO[Any]],
    vcpu_fds: Dict[int, IO[Any]],
) -> None:
    fd_num = int(os.path.basename(entry.path))
    try:
        target = os.readlink(entry.path)
    except IOError:
        # file may be closed again or not backed by file
        return
    if target == "anon_inode:kvm-vm":
        vm_fds.append(pid_fd.get_fd(fd_num))
        return
    match = re.match(r"anon_inode:kvm-vcpu:(\d+)", target)
    if match:
        idx = int(match.group(1))
        if vcpu_fds.get(idx) is not None:
            for fd in chain(vcpu_fds.values(), vm_fds):
                fd.close()
            raise GuestError(
                "Found multiple vcpus with same id in process {pid}."
                + " Assume multiple VMs. This is not supported yet."
            )
        vcpu_fds[idx] = pid_fd.get_fd(fd_num)


def find_vm(pid: int) -> Optional[Guest]:
    vm_fds: List[IO[Any]] = []
    vcpu_fds: Dict[int, IO[Any]] = {}
    with pidfd.openpid(pid) as pid_fd:
        for entry in pid_fd.fds():
            _find_vm_fd(entry, pid_fd, vm_fds, vcpu_fds)
    if len(vm_fds) == 0:
        return None
    if len(vm_fds) > 1:
        for fd in chain(vcpu_fds.values(), vm_fds):
            fd.close()
        raise GuestError(
            "Found multiple vms in process {pid}." + " This is not supported yet."
        )
    if len(vcpu_fds) == 0:
        raise GuestError(
            "Found KVM instance with no vcpu in process {pid}."
        )
    return Guest(vm_fd=vm_fds[0], vcpu_fds=list(vcpu_fds.values()))
