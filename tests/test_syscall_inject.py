#!/usr/bin/env python3

import subprocess
import os
import tempfile
import signal
from typing import List
from kvm_pirate.inject_syscall import attach
from kvm_pirate.syscalls import SYSCALL_NAMES

import conftest


def compile_executable(source: str, target: str) -> None:
    cc = os.environ.get("CC", "cc")
    cmd = [cc, "-xc", "-", "-g", "-o", target, "-pthread"]
    print(" ".join(cmd))
    subprocess.run(cmd, text=True, input=source, check=True)


def test_syscall_inject(helpers: conftest.Helpers) -> None:
    with tempfile.TemporaryDirectory() as d:
        binary = os.path.join(d, "main")
        compile_executable(
            "\n".join([
                "#include <unistd.h>",
                "#include <stdio.h>",
                "int main() { " "  int a; a = read(0, &a, sizeof(a));",
                '  puts("OK");' "  return 0;",
                "}",
            ]),
            binary,
        )
        pipefds = os.pipe()
        with subprocess.Popen([binary], stdin=pipefds[0], stdout=subprocess.PIPE, text=True) as proc:
            os.close(pipefds[0])
            with attach(proc.pid) as ctx:
                res = ctx.syscall(SYSCALL_NAMES["getpid"])
                assert res == proc.pid
            os.close(pipefds[1])
            res = proc.wait()
            assert proc.stdout is not None
            assert proc.stdout.read() == "OK\n"


# Test if all threads are stopped properly and invoking system calls in one
# thread does not break other threads
def test_multi_threaded(helpers: conftest.Helpers) -> None:
    with tempfile.TemporaryDirectory() as d:
        binary = os.path.join(d, "main")
        with open(helpers.root().joinpath("threaded.c")) as f:
            source = f.read()
        compile_executable(
            source,
            binary,
        )
        with subprocess.Popen([binary], text=True, stdout=subprocess.PIPE) as proc:
            assert proc.stdout is not None
            line = proc.stdout.readline()
            assert line == "threads started\n"
            with attach(proc.pid) as ctx:
                res = ctx.syscall(SYSCALL_NAMES["gettid"])
                assert res == proc.pid
                res = ctx.syscall(SYSCALL_NAMES["gettid"])
                assert res == proc.pid
            proc.send_signal(signal.SIGTERM)
            proc.wait(5)
            line = proc.stdout.read()
            assert line == "OK\n"
