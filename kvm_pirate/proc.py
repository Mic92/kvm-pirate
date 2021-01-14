#!/usr/bin/env python3

import os
from contextlib import contextmanager
from typing import Generator, Iterator


class Pid:
    def __init__(self, fd: int):
        self.fd = fd

    # this is less racy because of the pid file descriptor
    def fds(self) -> Iterator["os.DirEntry[str]"]:
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
