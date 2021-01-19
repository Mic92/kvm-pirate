#!/usr/bin/env python3

import os
import shutil
import tarfile
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).parent.resolve()

# don't generate all for now
whitelist = set(["powerpc", "arm", "arm64", "x86_64", "i386"])


# From https://github.com/hrw/syscalls-table/
def main() -> None:
    URL = "https://github.com/hrw/syscalls-table/archive/master.tar.gz"
    ROOT = Path(__file__).parent.resolve()
    with urllib.request.urlopen(URL) as source:
        with TemporaryDirectory() as tmp:
            archive_name = os.path.join(tmp, "master.tar.gz")
            with open(archive_name, "w+b") as archive_fd:
                shutil.copyfileobj(source, archive_fd)
            tar = tarfile.open(name=archive_name, mode="r")
            try:
                for name in tar.getnames():
                    if not name.startswith("syscalls-table-master/tables/syscalls"):
                        continue
                    arch = os.path.basename(name).split("-")[1]
                    if arch not in whitelist:
                        continue
                    path = ROOT.joinpath("syscalls", arch + ".py")
                    with open(path, "w") as f:
                        f.write(
                            """# GENERERATED by generate_syscalls.py
SYSCALL_NAMES = {
"""
                        )
                        content = tar.extractfile(name)
                        assert content is not None
                        for line in content.read().decode("utf-8").split("\n"):
                            syscall_spec = line.split("\t")
                            if len(syscall_spec) < 2:
                                continue
                            syscall, num = syscall_spec
                            f.write(f'    "{syscall}": {num},\n')
                        f.write("}\n")
            finally:
                tar.close()


if __name__ == "__main__":
    main()
