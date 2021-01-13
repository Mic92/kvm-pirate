#!/usr/bin/env python3

import os
from typing import Iterator, Generator
from contextlib import contextmanager


class Pid:
    def __init__(self, fd: int):
        self.fd = fd

    # this is less racy because of the pid file descriptor
    def fds(self) -> Iterator[os.DirEntry]:
        with os.scandir(f"/proc/{os.getpid()}/fd/{self.fd}/fd") as it:
            for entry in it:
                yield entry


@contextmanager
def openpid(pid: int) -> Generator[Pid, None, None]:
    proc_fd = os.open(f"/proc/{pid}", os.O_PATH)
    try:
        yield Pid(proc_fd)
    finally:
        os.close(proc_fd)
