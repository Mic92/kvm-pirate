#!/usr/bin/env python3

import argparse
import sys
from typing import NoReturn

from .coredump import generate_coredump
from .kvm import GuestError, Hypervisor, get_hypervisor


def die(msg: str) -> NoReturn:
    print(msg, file=sys.stderr)
    sys.exit(1)


def inspect_vm(args: argparse.Namespace, vm: Hypervisor) -> None:
    slots = vm.get_maps()
    for slot in slots:
        print(
            f"vm mem: 0x{slot.start:x} -> 0x{slot.stop:x} (physical 0x{slot.physical_start:x})"
        )


def coredump_vm(args: argparse.Namespace, vm: Hypervisor) -> None:
    slots = vm.get_maps()
    generate_coredump(vm.pid, slots)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inspect KVM-based VMs.")
    subparsers = parser.add_subparsers(
        title="subcommands", description="valid subcommands"
    )
    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.set_defaults(func=inspect_vm)
    inspect_parser.add_argument("pid", type=int)

    coredump_parser = subparsers.add_parser("coredump")
    coredump_parser.set_defaults(func=coredump_vm)
    coredump_parser.add_argument("pid", type=int)

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    try:
        hv = get_hypervisor(args.pid)
    except GuestError as err:
        die(f"Cannot access VM: {err}")
    if hv is None:
        die(f"No kvm instance found for pid {args.pid}")
    args.func(args, hv)


if __name__ == "__main__":
    main()
