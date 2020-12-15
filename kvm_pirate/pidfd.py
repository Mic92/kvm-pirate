import ctypes
import os
import sys
import errno
from contextlib import contextmanager

from typing import IO, Any, Iterator, Generator, Optional, Type, Tuple

libc = ctypes.CDLL(None)

get_errno_loc = libc.__errno_location
get_errno_loc.restype = ctypes.POINTER(ctypes.c_int)


def errcheck(
    ret: Optional[Type["ctypes._CData"]],
    func: "ctypes._FuncPointer",
    args: Tuple["ctypes._CData", ...],
) -> "ctypes._CData":
    assert isinstance(ret, int)
    if ret < 0:
        e = get_errno_loc()[0]
        raise OSError(e, os.strerror(e))
    return ret


syscall = libc.syscall
# don't know how to please mypy here
syscall.errcheck = errcheck  # type: ignore

# FIXME mips uses different numbers here
NR_SYS_pidfd_open = 434
NR_SYS_pidfd_getfd = 438


class PidFile:
    def __init__(self, pid_fd: int, proc_fd: int):
        self.pid_fd = pid_fd
        self.proc_fd = proc_fd

    def get_fd(self, targetfd: int, flags: int = 0, mode: str = "r") -> IO[Any]:
        fd = syscall(NR_SYS_pidfd_getfd, self.pid_fd, targetfd, flags)
        return os.fdopen(fd, mode)

    # this is less racy because of the pid file descriptor
    def fds(self) -> Iterator[os.DirEntry]:
        with os.scandir(f"/proc/{os.getpid()}/fd/{self.proc_fd}/fd") as it:
            for entry in it:
                yield entry


@contextmanager
def openpid(pid: int) -> Generator[PidFile, None, None]:
    proc_fd = os.open(f"/proc/{pid}", os.O_PATH)
    try:
        pid_fd = syscall(NR_SYS_pidfd_open, pid, 0)
        yield PidFile(pid_fd, proc_fd)
    finally:
        os.close(proc_fd)
        if pid_fd is not None:
            os.close(pid_fd)


def has_pidfd_getfd() -> bool:
    with openpid(os.getpid()) as pid_fd:
        try:
            pid_fd.get_fd(sys.stdout.fileno()).close()
            return True
        except OSError as e:
            if e.errno != errno.ENOSYS:
                raise e
            return False
