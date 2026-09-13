/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The guest address-space unit on its own.
 *
 * Three properties matter here and none of them needs a real mapping. The
 * first is the low-address policy: a relocatable module is reserved from a
 * cursor below 4 GiB and the cursor advances, because the portable mapper
 * refuses a PE32 image the guest could not address. The second is the bound:
 * a backend that refuses every candidate must not turn one reservation into a
 * walk of the whole window, and the unit has to say that it gave up. The third
 * is the contract with the backend underneath - every forwarded call must name
 * the caller's *own* context, which is what a stateful backend needs and what
 * the gate used to get wrong by borrowing that field for itself.
 */
#include "../src/pw_guest_vm.h"

#include <assert.h>
#include <string.h>

typedef struct FakeBackend {
    unsigned reserves;
    unsigned reserve_at_calls;
    unsigned commits;
    unsigned releases;
    unsigned fail_reserve_at;       /* refuse every exact candidate */
    unsigned exact;
} FakeBackend;

static int fake_region(uint64_t address, size_t bytes, PwVmRegion *out)
{
    out->write_base = (void *)(uintptr_t)address;
    out->exec_base = (void *)(uintptr_t)address;
    out->bytes = bytes;
    out->alignment = 0x1000u;
    out->handle = NULL;
    return PW_OK;
}

static int fake_reserve(void *context, size_t bytes, size_t alignment,
                        PwVmRegion *out)
{
    FakeBackend *fake = context;

    assert(fake != NULL);
    fake->reserves++;
    (void)alignment;
    /* The fallback a real backend would choose: somewhere high, which is
     * exactly what a PE32 image cannot use. */
    return fake_region(0x7000000000ull, bytes, out);
}

static int fake_reserve_at(void *context, uint64_t address, size_t bytes,
                           size_t alignment, PwVmRegion *out)
{
    FakeBackend *fake = context;

    assert(fake != NULL);
    fake->reserve_at_calls++;
    (void)alignment;
    if (fake->fail_reserve_at)
        return PW_ERR_VM;
    return fake_region(address, bytes, out);
}

static int fake_commit(void *context, const PwVmRegion *region, size_t offset,
                       size_t bytes, unsigned protection)
{
    FakeBackend *fake = context;

    assert(fake != NULL);
    fake->commits++;
    (void)region; (void)offset; (void)bytes; (void)protection;
    return PW_OK;
}

static int fake_protect(void *context, const PwVmRegion *region, size_t offset,
                        size_t bytes, unsigned protection)
{
    (void)region; (void)offset; (void)bytes; (void)protection;
    (void)context;
    return PW_OK;
}

static int fake_release(void *context, PwVmRegion *region)
{
    FakeBackend *fake = context;

    assert(fake != NULL);
    fake->releases++;
    (void)region;
    return PW_OK;
}

static FakeBackend fake;

static PwVmBackend backend_with(FakeBackend *fake, unsigned exact,
                                unsigned fail_reserve_at)
{
    const PwVmBackend backend = {
        .context = fake,
        .capabilities = exact ? PW_VM_CAP_EXACT_ADDRESS : 0u,
        .page_bytes = 0x1000u,
        .reserve = fake_reserve,
        .commit = fake_commit,
        .protect = fake_protect,
        .release = fake_release,
        .reserve_at = fake_reserve_at,
    };

    fake->fail_reserve_at = fail_reserve_at;
    return backend;
}

int main(void)
{
    PwGuestVm vm;
    PwVmRegion region;
    PwVmBackend backend;
    unsigned first_calls;

    /* A backend that can place an exact reservation: the first candidate is
     * used and the cursor moves past it. */
    memset(&fake, 0, sizeof(fake));
    backend = backend_with(&fake, 1u, 0u);
    pw_guest_vm_init(&vm, &backend);
    assert(pw_guest_vm_backend(&vm) != NULL);
    assert(pw_guest_vm_backend(&vm)->context == &vm);
    assert(pw_guest_vm_backend(&vm)->capabilities == PW_VM_CAP_EXACT_ADDRESS);
    /* The vtable handed out wraps the reservation; it is not the backend's. */
    assert(pw_guest_vm_backend(&vm)->reserve != backend.reserve);
    assert(pw_guest_vm_exhausted(&vm) == 0);
    assert(pw_guest_vm_backend(&vm)->reserve(&vm, 0x4000u, 0x1000u, &region) ==
           PW_OK);
    assert((uint64_t)(uintptr_t)region.exec_base == PW_GUEST_VM_LOW_BASE);
    assert(fake.reserve_at_calls == 1u && fake.reserves == 0u);
    assert(pw_guest_vm_exhausted(&vm) == 0);
    first_calls = fake.reserve_at_calls;
    assert(pw_guest_vm_backend(&vm)->reserve(&vm, 0x1000u, 0x1000u, &region) ==
           PW_OK);
    assert((uint64_t)(uintptr_t)region.exec_base ==
           PW_GUEST_VM_LOW_BASE + 0x4000u);
    assert(fake.reserve_at_calls == first_calls + 1u);

    /* The forwards must reach the backend with the backend's own context: the
     * fake asserts on it, so a wrapper that passed itself instead would abort
     * here rather than silently misbehave on a stateful backend. */
    assert(pw_guest_vm_backend(&vm)->reserve_at(&vm, 0x10000000u, 0x1000u,
                                                0x1000u, &region) == PW_OK);
    assert(pw_guest_vm_backend(&vm)->commit(&vm, &region, 0u, 0x1000u,
                                            PW_PROT_READ) == PW_OK);
    assert(pw_guest_vm_backend(&vm)->release(&vm, &region) == PW_OK);
    assert(fake.commits == 1u && fake.releases == 1u);

    /* A backend that refuses every candidate: the unit stops after its budget
     * and says so, then takes the fallback the mapper above will refuse. */
    memset(&fake, 0, sizeof(fake));
    backend = backend_with(&fake, 1u, 1u);
    pw_guest_vm_init(&vm, &backend);
    assert(pw_guest_vm_backend(&vm)->reserve(&vm, 0x4000u, 0x1000u, &region) ==
           PW_OK);
    assert(fake.reserve_at_calls == PW_GUEST_VM_MAX_CANDIDATES);
    assert(fake.reserves == 1u);
    assert(pw_guest_vm_exhausted(&vm) == 1);
    assert((uint64_t)(uintptr_t)region.exec_base > 0x100000000ull);
    /* The cursor starts again, so the next attempt begins at the bottom. */
    assert(pw_guest_vm_backend(&vm)->reserve(&vm, 0x4000u, 0x1000u, &region) ==
           PW_OK);
    assert(fake.reserve_at_calls == 2u * PW_GUEST_VM_MAX_CANDIDATES);

    /* A backend without exact addressing keeps its plain reservation and is
     * never asked for an exact one. */
    memset(&fake, 0, sizeof(fake));
    backend = backend_with(&fake, 0u, 0u);
    pw_guest_vm_init(&vm, &backend);
    assert(pw_guest_vm_backend(&vm)->reserve(&vm, 0x4000u, 0x1000u, &region) ==
           PW_OK);
    assert(fake.reserves == 1u && fake.reserve_at_calls == 0u);
    assert(pw_guest_vm_exhausted(&vm) == 0);
    return 0;
}
