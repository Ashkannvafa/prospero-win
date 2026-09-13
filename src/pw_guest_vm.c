/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_guest_vm.h"

#include <string.h>

/*
 * Every forwarded call names the caller's own context, never ours: that is the
 * whole point of keeping `base` and `low` apart.
 */
static int guest_vm_reserve_at(void *context, uint64_t address, size_t bytes,
                               size_t alignment, PwVmRegion *out)
{
    PwGuestVm *vm = context;

    return vm->base.reserve_at(vm->base.context, address, bytes, alignment,
                               out);
}

static int guest_vm_commit(void *context, const PwVmRegion *region,
                           size_t offset, size_t bytes, unsigned protection)
{
    PwGuestVm *vm = context;

    return vm->base.commit(vm->base.context, region, offset, bytes,
                           protection);
}

static int guest_vm_protect(void *context, const PwVmRegion *region,
                            size_t offset, size_t bytes, unsigned protection)
{
    PwGuestVm *vm = context;

    return vm->base.protect(vm->base.context, region, offset, bytes,
                            protection);
}

static int guest_vm_release(void *context, PwVmRegion *region)
{
    PwGuestVm *vm = context;

    return vm->base.release(vm->base.context, region);
}

/*
 * The plain reservation a relocatable module gets: an exact low candidate
 * first, then - if the budget runs out - whatever the backend would have
 * chosen, which the mapper above will refuse for a PE32 image. The budget is
 * what keeps a backend that refuses every candidate from turning one mapping
 * attempt into 196 608 backend calls.
 */
static int guest_vm_reserve(void *context, size_t bytes, size_t alignment,
                            PwVmRegion *out)
{
    PwGuestVm *vm = context;

    if ((vm->base.capabilities & PW_VM_CAP_EXACT_ADDRESS) != 0u &&
        bytes != 0u && bytes <= PW_GUEST_VM_MAX_IMAGE_BYTES) {
        const uint32_t step = alignment != 0u ? (uint32_t)alignment : 0x1000u;
        uint32_t candidate = (vm->cursor + step - 1u) & ~(step - 1u);
        uint32_t tried = 0u;

        vm->exhausted = 0u;
        while (tried < PW_GUEST_VM_MAX_CANDIDATES &&
               (uint64_t)candidate + bytes <= 0x100000000ull &&
               candidate < PW_GUEST_VM_LOW_LIMIT) {
            if (vm->base.reserve_at(vm->base.context, candidate, bytes,
                                    alignment, out) == PW_OK) {
                vm->cursor = candidate + (uint32_t)bytes;
                return PW_OK;
            }
            ++tried;
            if (candidate > PW_GUEST_VM_LOW_LIMIT - step)
                break;
            candidate += step;
        }
        vm->exhausted = 1u;
        vm->cursor = PW_GUEST_VM_LOW_BASE;
    }
    return vm->base.reserve(vm->base.context, bytes, alignment, out);
}

void pw_guest_vm_init(PwGuestVm *vm, const PwVmBackend *base)
{
    memset(vm, 0, sizeof(*vm));
    vm->base = *base;
    vm->low = *base;
    vm->low.context = vm;
    /* Only the callbacks the backend actually has are wrapped; a backend
     * without exact addressing keeps whatever it had, and the capability flags
     * the callers check are the caller's own. */
    if (base->reserve)
        vm->low.reserve = guest_vm_reserve;
    if (base->reserve_at)
        vm->low.reserve_at = guest_vm_reserve_at;
    if (base->commit)
        vm->low.commit = guest_vm_commit;
    if (base->protect)
        vm->low.protect = guest_vm_protect;
    if (base->release)
        vm->low.release = guest_vm_release;
    vm->cursor = PW_GUEST_VM_LOW_BASE;
}

const PwVmBackend *pw_guest_vm_backend(PwGuestVm *vm)
{
    return &vm->low;
}

int pw_guest_vm_exhausted(const PwGuestVm *vm)
{
    return vm->exhausted != 0u;
}

void pw_guest_vm_reset(PwGuestVm *vm)
{
    vm->cursor = PW_GUEST_VM_LOW_BASE;
    vm->exhausted = 0u;
}
