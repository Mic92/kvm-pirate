#!/usr/bin/env python3

import os
import re
from contextlib import contextmanager
from typing import Generator, Iterator
from dataclasses import dataclass
from mmap import MAP_PRIVATE, MAP_SHARED, PROT_EXEC, PROT_READ, PROT_WRITE
from typing import List, Optional


@dataclass
class Mapping:
    start: int
    stop: int
    flags: int
    offset: int
    major_dev: int
    minor_dev: int
    inode: int
    pathname: str

    @property
    def size(self) -> int:
        return self.stop - self.start

    def __repr__(self) -> str:
        return "%s(%r, start=%#x, stop=%#x, size=%#x, flags=%#x, offset=%#x)" % (
            self.__class__.__name__,
            self.pathname,
            self.start,
            self.stop,
            self.size,
            self.flags,
            self.offset,
        )


@dataclass
class KvmMapping(Mapping):
    physical_start: int
    hv_mapping: Mapping


class Pid:
    def __init__(self, fd: int):
        self.fd = fd

    def entry(self, name: str) -> str:
        # this is less racy because of the pid file descriptor
        return f"/proc/{os.getpid()}/fd/{self.fd}/{name}"

    def fds(self) -> Iterator["os.DirEntry[str]"]:
        with os.scandir(self.entry("fd")) as it:
            for entry in it:
                yield entry

    def maps(self) -> List[Mapping]:
        mappings: List[Mapping] = []
        with open(self.entry("maps")) as f:
            for line in f:
                mappings.append(_parse_line(line))
        return mappings


def _parse_flags(field: str) -> int:
    assert len(field) == 4
    bits = 0
    if field[0] == "r":
        bits |= PROT_READ
    if field[1] == "w":
        bits |= PROT_WRITE
    if field[2] == "x":
        bits |= PROT_EXEC
    if field[3] == "p":
        bits |= MAP_PRIVATE
    else:
        bits |= MAP_SHARED
    return bits


def _parse_line(line: str) -> Mapping:
    fields = line.split(" ", 5)
    _range = fields[0].split("-", 1)
    start = int(_range[0], 16)
    stop = int(_range[1], 16)
    permissions = _parse_flags(fields[1])
    offset = int(fields[2], 16)
    dev = fields[3].split(":", 1)
    major_dev = int(dev[0], 16)
    minor_dev = int(dev[1], 16)
    inode = int(fields[4])
    # strip space around path
    path = re.sub(r"^[^[/]*|\n$", "", fields[5])
    return Mapping(start, stop, permissions, offset, major_dev, minor_dev, inode, path)


def find_mapping(mappings: List[Mapping], ip: int) -> Optional[Mapping]:
    for mapping in mappings:
        if mapping.start <= ip and ip < mapping.stop:
            return mapping
    return None


def find_location(mappings: List[Mapping], ip: int) -> str:
    mapping = find_mapping(mappings, ip)
    if mapping is None:
        return "0x{:x} (umapped)".format(ip)
    else:
        offset = ip - mapping.start + mapping.offset * 4096
        return "0x{:x} ({}+{})".format(ip, mapping.pathname, offset)


@contextmanager
def openpid(pid: int) -> Generator[Pid, None, None]:
    proc_fd = os.open(f"/proc/{pid}", os.O_PATH)
    try:
        yield Pid(proc_fd)
    finally:
        os.close(proc_fd)
