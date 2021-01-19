from typing import Any, List
import ctypes
from typing import Type
import time

from bcc import BPF

from . import kvm

bpf_text = """
#include <linux/kvm_host.h>

struct memslot {
    gfn_t base_gfn;
    unsigned long npages;
    unsigned long userspace_addr;
};

typedef struct {
  size_t address_space_num;
  size_t mem_slots_num;
  struct memslot memslots[KVM_ADDRESS_SPACE_NUM][KVM_MEM_SLOTS_NUM];
} out_t;
BPF_PERCPU_ARRAY(slots, out_t, 1);

BPF_PERF_OUTPUT(memslots);

void kvm_vm_ioctl(struct pt_regs *ctx, struct file *filp) {
    size_t i = 0, j = 0;
    u32 idx = 0;
    struct kvm *kvm = (struct kvm *)filp->private_data;

    bpf_trace_printk("Hello, World!\\n");
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != TARGET_PID) {
        return;
    }

    out_t *out = slots.lookup(&idx);
    if (!out) {
      return;
    }

    out->address_space_num = KVM_ADDRESS_SPACE_NUM;
    out->mem_slots_num = KVM_MEM_SLOTS_NUM;

    for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
        for (j = 0; j < KVM_MEM_SLOTS_NUM; j++) {
            struct kvm_memory_slot *in_slot = &kvm->memslots[i]->memslots[j];
            struct memslot *out_slot = &out->memslots[i][j];
            out_slot->base_gfn = in_slot->base_gfn;
            out_slot->npages = in_slot->npages;
            out_slot->userspace_addr = in_slot->userspace_addr;
        }
    }
    memslots.perf_submit(ctx, out, sizeof(*out));
}
"""


class Memslot(ctypes.Structure):
    _fields_ = [
        ("base_gfn", ctypes.c_uint64),
        ("npages", ctypes.c_ulong),
        ("userspace_addr", ctypes.c_ulong),
    ]


class EventHeader(ctypes.Structure):
    _fields_ = [
        ("address_space_num", ctypes.c_size_t),
        ("mem_slots_num", ctypes.c_size_t),
    ]


def event_structure(header: EventHeader) -> Type[ctypes.Structure]:
    assert header.address_space_num != 0
    assert header.mem_slots_num != 0

    class Event(ctypes.Structure):
        _fields_ = [
            ("header", EventHeader),
            ("memslots", Memslot * header.address_space_num * header.mem_slots_num),
        ]

    return Event


class MemorySlot:
    pass


def bpf_prog(pid: int) -> BPF:
    return BPF(text=bpf_text, cflags=[f"-DTARGET_PID={pid}"])


def get_memlots(hv: kvm.Hypervisor) -> List[MemorySlot]:
    # initialize BPF

    memory_slots: List[MemorySlot] = []

    bpf = bpf_prog(hv.pid)

    memslots = []

    def get_memslot(cpu: int, data: Any, size: int) -> None:
        header = ctypes.cast(data, ctypes.POINTER(EventHeader)).contents
        event_cls = event_structure(header)
        event = ctypes.cast(data, ctypes.POINTER(event_cls)).contents
        memslots.append(event.memslots)

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
    return memory_slots


if __name__ == "__main__":
    bpf_prog(0)
