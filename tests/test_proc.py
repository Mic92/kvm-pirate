import os
from kvm_pirate import proc
import ctypes
import mmap


def test_maps():
    with proc.openpid(os.getpid()) as pid_fd:
        mappings = pid_fd.maps()
    ptr = ctypes.cast(ctypes.pointer(ctypes.c_int()), ctypes.c_void_p).value
    mapping = proc.find_mapping(mappings, ptr)
    maps = "\n".join(map(repr, mappings))
    assert mapping is not None, f"could not find {ptr} in :\n{maps}"
    assert mapping.flags == mmap.PROT_READ | mmap.PROT_WRITE | mmap.MAP_PRIVATE
