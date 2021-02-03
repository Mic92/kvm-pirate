import ctypes
import resource
from typing import Any, List, Type

from bcc import BPF

try:
    # for mypy
    from . import kvm
except ImportError:
    pass

from . import proc

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
    def size(self) -> int:
        return int(resource.getpagesize() * self.npages)

    @property
    def end(self) -> int:
        return self.start + self.size

    @property
    def physical_start(self) -> int:
        return int(self.base_gfn * resource.getpagesize())

    def __repr__(self) -> str:
        return "%s(start=%#x, end=%#x, size=%#x, physical_start=%#x)" % (
            self.__class__.__name__,
            self.start,
            self.end,
            self.size,
            self.physical_start,
        )


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


def get_maps(hv: "kvm.Hypervisor") -> List[proc.KvmMapping]:
    # initialize BPF

    bpf = bpf_prog(hv.pid)

    memslots: List[MemSlot] = []

    def get_memslot(cpu: int, data: Any, size: int) -> None:
        header = ctypes.cast(data, ctypes.POINTER(ctypes.c_size_t)).contents
        event_cls = event_structure(header)
        event = ctypes.cast(data, ctypes.POINTER(event_cls)).contents
        memslots.clear()
        for memslot in event.memslots:
            # we don't own the data here
            copy = MemSlot()
            ctypes.pointer(copy)[0] = memslot
            memslots.append(copy)

    try:
        with hv.attach() as tracee:
            bpf.attach_kprobe(event="kvm_vm_ioctl", fn_name="kvm_vm_ioctl")
            bpf["memslots"].open_perf_buffer(get_memslot)
            tracee.check_extension(0)
        bpf.perf_buffer_poll()
    finally:
        # close perf reader
        del bpf
    assert len(memslots) > 0

    maps = []
    for memslot in memslots:
        mapping = proc.find_mapping(hv.mappings, memslot.start)
        assert mapping is not None
        attrs = mapping.__dict__
        attrs.update(
            physical_start=memslot.physical_start,
            start=mapping.start,
            stop=memslot.end,
            hv_mapping=mapping,
        )
        kvm_mapping = proc.KvmMapping(**attrs)
        assert kvm_mapping.start >= mapping.start
        assert kvm_mapping.stop <= mapping.stop
        maps.append(kvm_mapping)
    return maps


if __name__ == "__main__":
    bpf_prog(0)
