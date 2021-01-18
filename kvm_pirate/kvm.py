#!/usr/bin/env python3

import ctypes
import os
import re
from contextlib import contextmanager
from typing import Any, Dict, Generator, List, Optional

from . import inject_syscall, proc

GET_API_VERSION = 0xAE00
CREATE_VM = 0xAE01
SET_USER_MEMORY_REGION = 0x4020AE46
CHECK_EXTENSION = 0xAE03
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


class UserspaceMemoryRegion(ctypes.Structure):
    _fields_ = [
        ("slot", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("guest_phys_addr", ctypes.c_uint64),
        ("memory_size", ctypes.c_uint64),
        ("userspace_addr", ctypes.c_uint64),
    ]


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


class Tracee:
    def __init__(self, hypervisor: "Hypervisor", proc: inject_syscall.Process) -> None:
        self.hypervisor = hypervisor
        self.proc = proc

    def _vm_ioctl(self, request: int, arg: Any = 0) -> int:
        return self.proc.ioctl(self.hypervisor.vm_fd, request, arg)

    def _cpu_ioctl(self, cpu: int, request: int, arg: Any = 0) -> int:
        return self.proc.ioctl(self.hypervisor.vcpu_fds[cpu], request, arg)

    def get_regs(self, cpu: int) -> Regs:
        regs = Regs()
        try:
            self._cpu_ioctl(cpu, GET_REGS, regs)
            return regs
        except OSError as err:
            raise GuestError("Failed to get registers") from err

    def check_extension(self, cap: int) -> int:
        try:
            return self._vm_ioctl(CHECK_EXTENSION, cap)
        except OSError as err:
            raise GuestError("Failed to check extension") from err

    # XXX UserspaceMemoryRegion must be in tracee memory
    def set_user_memory_region(self, region: UserspaceMemoryRegion) -> None:
        try:
            ptr = ctypes.cast(ctypes.byref(region), ctypes.c_void_p).value
            self._vm_ioctl(SET_USER_MEMORY_REGION, ptr)
        except OSError as err:
            raise GuestError("Failed to set user memory region") from err

    def get_sregs(self, cpu: int) -> Sregs:
        sregs = Sregs()
        try:
            self._cpu_ioctl(cpu, GET_SREGS, sregs)
            return sregs
        except OSError as err:
            raise GuestError("Failed to get special registers") from err


# TODO multiple vms
class Hypervisor:
    def __init__(self, pid: int, vm_fd: int, vcpu_fds: List[int]) -> None:
        self.pid = pid
        self.vm_fd = vm_fd
        self.vcpu_fds = vcpu_fds

    @contextmanager
    def attach(self) -> Generator[Tracee, None, None]:
        with inject_syscall.attach(self.pid) as process:
            yield Tracee(self, process)

    def cpu_count(self) -> int:
        return len(self.vcpu_fds)

    def exit(self) -> None:
        os.close(self.vm_fd)
        for fd in self.vcpu_fds:
            os.close(fd)


def _find_vm_fd(
    entry: "os.DirEntry[str]",
    vm_fds: List[int],
    vcpu_fds: Dict[int, int],
) -> None:
    fd_num = int(os.path.basename(entry.path))
    try:
        target = os.readlink(entry.path)
    except IOError:
        # file may be closed again or not backed by file
        return
    if target == "anon_inode:kvm-vm":
        vm_fds.append(fd_num)
        return
    match = re.match(r"anon_inode:kvm-vcpu:(\d+)", target)
    if match:
        idx = int(match.group(1))
        if vcpu_fds.get(idx) is not None:
            raise GuestError(
                "Found multiple vcpus with same id in process {pid}."
                + " Assume multiple VMs. This is not supported yet."
            )
        vcpu_fds[idx] = fd_num


def find_vm(pid: int) -> Optional[Hypervisor]:
    vm_fds: List[int] = []
    vcpu_fds: Dict[int, int] = {}
    with proc.openpid(pid) as pid_fd:
        for entry in pid_fd.fds():
            _find_vm_fd(entry, vm_fds, vcpu_fds)
    if len(vm_fds) == 0:
        return None
    if len(vm_fds) > 1:
        raise GuestError(
            "Found multiple vms in process {pid}." + " This is not supported yet."
        )
    if len(vcpu_fds) == 0:
        raise GuestError("Found KVM instance with no vcpu in process {pid}.")
    return Hypervisor(pid=pid, vm_fd=vm_fds[0], vcpu_fds=list(vcpu_fds.values()))
