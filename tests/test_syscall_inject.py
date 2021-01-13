#!/usr/bin/env python3

import subprocess
import os
import tempfile
from typing import List
from kvm_pirate.inject_syscall import attach
from kvm_pirate.syscalls import SYSCALL_NAMES

import conftest


def compile_executable(lines: List[str], target: str) -> None:
    cc = os.environ.get("CC", "cc")
    source = "\n".join(lines)
    cmd = [cc, "-xc", "-", "-g", "-o", target]
    print(" ".join(cmd))
    subprocess.run(cmd, text=True, input=source, check=True)


def test_syscall_inject(helpers: conftest.Helpers) -> None:
    with tempfile.TemporaryDirectory() as d:
        binary = os.path.join(d, "main")
        compile_executable(
            [
                "#include <unistd.h>",
                "#include <stdio.h>",
                "int main() { " "  int a; a = read(0, &a, sizeof(a));",
                '  puts("OK");' "  return 0;",
                "}",
            ],
            binary,
        )
        pipefds = os.pipe()
        proc = subprocess.Popen(
            [binary], stdin=pipefds[0], stdout=subprocess.PIPE, text=True
        )
        os.close(pipefds[0])
        with attach(proc.pid) as ctx:
            res = ctx.syscall(SYSCALL_NAMES["getpid"])
            assert res == proc.pid
        os.close(pipefds[1])
        res = proc.wait()
        assert proc.stdout is not None
        assert proc.stdout.read() == "OK\n"
