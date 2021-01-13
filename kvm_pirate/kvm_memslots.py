from typing import Any, List

from bcc import BPF

from . import kvm

bpf_text = """
#include <linux/kvm_host.h>

struct memslot_t {
    gfn_t base_gfn;
    unsigned long npages;
    unsigned long userspace_addr;
};
typedef struct {
  struct memslot_t memslots[KVM_ADDRESS_SPACE_NUM][KVM_MEM_SLOTS_NUM];
} out_t;
BPF_PERCPU_ARRAY(slots, out_t, 1);

BPF_PERF_OUTPUT(events);

void kprobe__kvm_set_memory_region(struct pt_regs *ctx, struct kvm *kvm) {
    size_t i = 0, j = 0;
    u32 idx = 0;

    bpf_trace_printk("match!\\n");

    out_t *out = slots.lookup(&idx);
    if (!out) {
      return;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != TARGET_PID) {
        return;
    }
    for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
        for (j = 0; j < KVM_ADDRESS_SPACE_NUM; j++) {
            struct kvm_memory_slot *in_slot = &kvm->memslots[i]->memslots[j];
            struct memslot_t *out_slot = &out->memslots[i][j];
            out_slot->base_gfn = in_slot->base_gfn;
            out_slot->npages = in_slot->npages;
            out_slot->userspace_addr = in_slot->userspace_addr;
        }
    }
    events.perf_submit(ctx, out, sizeof(out));
}
"""


class MemorySlot:
    pass


def bpf_prog(pid: int) -> BPF:
    return BPF(text=bpf_text, cflags=[f"-DTARGET_PID={pid}"])


def get_memlots(hv: kvm.Hypervisor) -> List[MemorySlot]:
    # initialize BPF
    b = bpf_prog(hv.pid)
    memory_slots: List[MemorySlot] = []

    def print_event(cpu: int, data: Any, size: int) -> None:
        event = b["events"].event(data)
        memory_slots = event[0]
        print(memory_slots)

    b["events"].open_perf_buffer(print_event)
    with hv.attach() as tracee:
        try:
            region = kvm.UserspaceMemoryRegion()
            tracee.set_user_memory_region(region)
        except kvm.GuestError as e:
            print(e)
    b.perf_buffer_poll()
    return memory_slots


if __name__ == "__main__":
    bpf_prog(0)
