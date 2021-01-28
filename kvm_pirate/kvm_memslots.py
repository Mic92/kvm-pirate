from typing import Any, List
import ctypes
import resource
import logging
from typing import Type
from bcc import BPF

from . import kvm

logger = logging.getLogger(__name__)

DEBUG = True

bpf_text = """
#include <linux/kvm_host.h>

struct memslot {
    gfn_t base_gfn;
    unsigned long npages;
    unsigned long userspace_addr;
};

typedef struct {
  size_t used_slots;
  struct memslot memslots[KVM_MEM_SLOTS_NUM];
} out_t;

BPF_PERCPU_ARRAY(slots, out_t, 1);

BPF_PERF_OUTPUT(memslots);

void kvm_vm_ioctl(struct pt_regs *ctx, struct file *filp) {
    struct kvm *kvm = (struct kvm *)filp->private_data;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != TARGET_PID) {
        return;
    }

    u32 idx = 0;
    out_t *out = slots.lookup(&idx);
    if (!out) {
      return;
    }

    // On x86 there is also a second address space for system management mode in memslots[1]
    // however we dont care about about this one
    out->used_slots = kvm->memslots[0]->used_slots;
    for (size_t i = 0; i < KVM_MEM_SLOTS_NUM; i++) {
      struct kvm_memory_slot *in_slot = &kvm->memslots[0]->memslots[i];
      struct memslot *out_slot = &out->memslots[i];

      out_slot->base_gfn = in_slot->base_gfn;
      out_slot->npages = in_slot->npages;
      out_slot->userspace_addr = in_slot->userspace_addr;
    }
    memslots.perf_submit(ctx, out, sizeof(*out));
}
"""


class MemSlot(ctypes.Structure):
    _fields_ = [
        ("base_gfn", ctypes.c_uint64),
        ("npages", ctypes.c_ulong),
        ("userspace_addr", ctypes.c_ulong),
    ]

    @property
    def start(self) -> int:
        return int(self.userspace_addr)

    @property
    def end(self) -> int:
        return int(self.start + resource.getpagesize() * self.npages)

    @property
    def physical_start(self) -> int:
        return int(self.base_gfn * resource.getpagesize())


def event_structure(header: ctypes.c_size_t) -> Type[ctypes.Structure]:
    assert header.value != 0
    used_slots = header.value

    class Event(ctypes.Structure):
        _fields_ = [
            ("used_slots", ctypes.c_size_t),
            ("memslots", MemSlot * used_slots),
        ]

    return Event


def bpf_prog(pid: int) -> BPF:
    return BPF(text=bpf_text, cflags=[f"-DTARGET_PID={pid}"])


def get_memlots(hv: kvm.Hypervisor) -> List[MemSlot]:
    # initialize BPF

    bpf = bpf_prog(hv.pid)

    memslots: List[MemSlot] = []

    def get_memslot(cpu: int, data: Any, size: int) -> None:
        header = ctypes.cast(data, ctypes.POINTER(ctypes.c_size_t)).contents
        event_cls = event_structure(header)
        event = ctypes.cast(data, ctypes.POINTER(event_cls)).contents
        memslots.clear()
        memslots.extend(event.memslots)

    try:
        with hv.attach() as tracee:
            bpf.attach_kprobe(event="kvm_vm_ioctl", fn_name="kvm_vm_ioctl")
            bpf["memslots"].open_perf_buffer(get_memslot)
            try:
                tracee.check_extension(0)
            except kvm.GuestError as e:
                print(e)
        bpf.perf_buffer_poll()
    finally:
        # close perf reader
        del bpf
    assert len(memslots) > 0
    for slot in memslots:
        if slot.base_gfn == 0 and slot.npages == 0 and slot.userspace_addr == 0:
            continue
        logger.info(
            f"vm mem: 0x{slot.start:x} -> 0x{slot.end:x} (physical 0x{slot.physical_start:x})"
        )

    return memslots


if __name__ == "__main__":
    bpf_prog(0)
