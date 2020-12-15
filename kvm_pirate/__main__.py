#!/usr/bin/env python3

import sys

from .kvm import find_vm, GuestError
from .pidfd import has_pidfd_getfd


def die(msg: str):
    print(msg, file=sys.stderr)
    sys.exit(1)


def main() -> None:
    if len(sys.argv) < 2:
        die(f"USAGE: {sys.argv[0]} pid")
    if not has_pidfd_getfd():
        die("pidfd_getfd syscall is not supported. "
            "Please upgrade to your kernel to at least 5.6.")
    try:
        pid = int(sys.argv[1])
    except ValueError as e:
        die(f"Pid is not a number: {e}")
    try:
        vm = find_vm(pid)
    except GuestError as err:
        die(f"Cannot access VM: {err}")
    if vm is None:
        die(f"No kvm instance found for pid {pid}")


if __name__ == "__main__":
    main()
