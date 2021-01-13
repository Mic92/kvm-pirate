#!/usr/bin/env python3

import sys

from .kvm import find_vm, GuestError
from .kvm_memslots import get_memlots
from typing import NoReturn


def die(msg: str) -> NoReturn:
    print(msg, file=sys.stderr)
    sys.exit(1)


def main() -> None:
    if len(sys.argv) < 2:
        die(f"USAGE: {sys.argv[0]} pid")
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
    slots = get_memlots(vm)
    print(slots)


if __name__ == "__main__":
    main()
