#!/usr/bin/env python3

import sys
import ctypes
import resource
import mmap
from typing import IO, List, NoReturn

from .elf import ELFARCH, ELFCLASS, ELFDATA2, Ehdr, Phdr, Shdr
from .elf.consts import ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3, ET_CORE, EV_CURRENT, PT_LOAD
from .proc import KvmMapping
from .libc import libc, iovec


def die(msg: str) -> NoReturn:
    print(msg, file=sys.stderr)
    sys.exit(1)


def page_align(v: int) -> int:
    return (v + resource.getpagesize() - 1) & ~(resource.getpagesize() - 1)


def write_corefile(pid: int, core_file: IO[bytes], slots: List[KvmMapping]) -> None:
    ehdr = Ehdr()
    ehdr.e_ident[0] = ELFMAG0
    ehdr.e_ident[1] = ELFMAG1
    ehdr.e_ident[2] = ELFMAG2
    ehdr.e_ident[3] = ELFMAG3
    ehdr.e_ident[4] = ELFCLASS
    ehdr.e_ident[5] = ELFDATA2
    ehdr.e_type = ET_CORE
    ehdr.e_machine = ELFARCH
    ehdr.e_version = EV_CURRENT
    ehdr.e_phoff = ctypes.sizeof(Ehdr)
    ehdr.e_ehsize = ctypes.sizeof(Ehdr)
    ehdr.e_phentsize = ctypes.sizeof(Phdr)
    ehdr.e_phnum = len(slots)
    ehdr.e_shentsize = ctypes.sizeof(Shdr)

    section_headers = (Phdr * ehdr.e_phnum)()
    offset = page_align(ctypes.sizeof(Ehdr) + ctypes.sizeof(section_headers))
    core_size = offset
    for ph, slot in zip(section_headers, slots):
        ph.p_type = PT_LOAD
        # FIXME, we could get this from /proc/<pid>/maps if we want
        ph.p_flags = 0
        ph.p_offset = core_size
        ph.p_vaddr = slot.start
        ph.p_paddr = 0
        ph.p_filesz = slot.size
        ph.p_memsz = slot.size
        ph.p_align = resource.getpagesize()
        core_size += slot.size

    src_iovecs = (iovec * len(slots))()
    dst_iovec = iovec()

    core_file.truncate(core_size)
    core_file.write(bytearray(ehdr))
    core_file.write(bytearray(section_headers))
    core_file.flush()

    buf = mmap.mmap(
        core_file.fileno(),
        core_size - offset,
        mmap.MAP_SHARED,
        mmap.PROT_WRITE,
        offset=offset,
    )
    try:
        c_void = ctypes.c_void_p.from_buffer(buf)  # type: ignore
        ptr = ctypes.addressof(c_void)
        dst_iovec.iov_base = ptr
        dst_iovec.iov_len = core_size - offset
        for iov, slot in zip(src_iovecs, slots):
            iov.iov_base = slot.start
            iov.iov_len = slot.size
        libc.process_vm_readv(pid, dst_iovec, 1, src_iovecs, len(src_iovecs), 0)
    finally:
        # gc references to buf so we can close it
        del ptr
        del c_void
        buf.close()


# This is not a memory-consitant snapshot because the VM still runs while copying the memory!
# However we are interested in where the kernel text is for now.
def generate_coredump(pid: int, maps: List[KvmMapping]) -> None:
    with open(f"/proc/{pid}/maps", "r") as f:
        print(f.read())
    with open(f"core.{pid}", "wb+") as core_file:
        write_corefile(pid, core_file, maps)
