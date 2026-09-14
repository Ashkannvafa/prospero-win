/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Teardown failures must not erase ownership.
 *
 * The final review found that a failed release dropped the only record of the
 * mapping in three places - a process page, a loader module and the engine's
 * region - so the mapping leaked and nobody could retry it. Each unit now keeps
 * what it failed to give back and says so, and this test injects the failure
 * with a backend double: the first attempt fails partway, the owner is still
 * there afterwards, and the second attempt (with the double disarmed) releases
 * everything.
 */
#include "../src/pw_guest_process.h"
#include "../src/pw_loader.h"
#include "../src/pw_vm_posix.h"
#include "../src/pw_x86_engine.h"

#include <assert.h>
#include <string.h>

typedef struct FaultBackend {
    const PwVmBackend *real;
    unsigned releases;              /* releases attempted */
    unsigned fail_release;          /* fail this ordinal (0 = never) */
    unsigned failed;                /* failures injected */
} FaultBackend;

static FaultBackend faults;

static int fault_reserve(void *context, size_t bytes, size_t alignment,
                         PwVmRegion *out)
{
    (void)context;
    return faults.real->reserve(faults.real->context, bytes, alignment, out);
}

static int fault_reserve_at(void *context, uint64_t address, size_t bytes,
                            size_t alignment, PwVmRegion *out)
{
    (void)context;
    return faults.real->reserve_at(faults.real->context, address, bytes,
                                   alignment, out);
}

static int fault_commit(void *context, const PwVmRegion *region, size_t offset,
                        size_t bytes, unsigned protection)
{
    (void)context;
    return faults.real->commit(faults.real->context, region, offset, bytes,
                               protection);
}

static int fault_protect(void *context, const PwVmRegion *region, size_t offset,
                         size_t bytes, unsigned protection)
{
    (void)context;
    return faults.real->protect(faults.real->context, region, offset, bytes,
                                protection);
}

static int fault_release(void *context, PwVmRegion *region)
{
    (void)context;
    faults.releases++;
    if (faults.fail_release != 0u && faults.releases >= faults.fail_release) {
        faults.failed++;
        return PW_ERR_VM;
    }
    return faults.real->release(faults.real->context, region);
}

static PwVmBackend wrap(const PwVmBackend *real)
{
    return (PwVmBackend){
        .context = NULL,
        .capabilities = real->capabilities,
        .page_bytes = real->page_bytes,
        .reserve = fault_reserve,
        .commit = fault_commit,
        .protect = fault_protect,
        .release = fault_release,
        .reserve_at = fault_reserve_at,
    };
}

/* The loader validates its provider up front even when the case under test
 * never opens a module: these two are never called. */
static int unused_open(void *context, const char *name, PwFileSpan *span)
{
    (void)context;
    (void)name;
    (void)span;
    return PW_ERR_NOT_FOUND;
}

static void unused_close(void *context, PwFileSpan *span)
{
    (void)context;
    (void)span;
}

/* The engine requires a source view up front; this case only tears it down. */
static int unused_source(void *opaque, uint32_t guest_pc,
                         const uint8_t **source, size_t *bytes)
{
    (void)opaque;
    (void)guest_pc;
    (void)source;
    (void)bytes;
    return PW_ERR_NOT_FOUND;
}

/* A process page that could not be given back stays owned, and a second
 * attempt releases it. */
static void process_pages_test(const PwVmBackend *wrapped)
{
    const PwGuestProcessConfig config = {
        .backend = wrapped, .stack_base = 0u, .stack_bytes = 0u,
        .root_module = "kernelbase.dll",
    };
    PwGuestProcess process;
    uint32_t addresses[PW_GUEST_PROCESS_PAGES];

    memset(&process, 0, sizeof(process));
    assert(pw_guest_process_create(&process, &config) == PW_OK);
    assert(process.mapped == PW_GUEST_PROCESS_PAGES);
    for (uint32_t index = 0u; index < PW_GUEST_PROCESS_PAGES; ++index)
        addresses[index] = (uint32_t)(uintptr_t)process.pages[index].exec_base;

    /* The unit owns three of the four pages (the parameters page belongs to
     * the guest's own call registry), so the second and third releases are
     * the ones injected. One goes back, two stay owned. */
    faults.fail_release = 2u;
    assert(pw_guest_process_release(&process, wrapped) == PW_ERR_VM);
    assert(process.released == 1u);
    assert(process.mapped == 2u);
    /* The first page went back, so it is gone; the two that refused are the
     * ones still in the inventory, compacted to the front. */
    assert((uint32_t)(uintptr_t)process.pages[0].exec_base == addresses[1]);
    assert((uint32_t)(uintptr_t)process.pages[1].exec_base == addresses[2]);
    assert(faults.failed >= 1u);

    /* With the backend healthy again, a retry gives back exactly what was
     * left, and the process owns nothing. */
    faults.fail_release = 0u;
    assert(pw_guest_process_release(&process, wrapped) == PW_OK);
    assert(process.mapped == 0u);
    assert(process.released == 2u);
}

/* A module whose mapping refuses to be released stays in the inventory. */
static void loader_module_test(const PwVmBackend *wrapped)
{
    PwLoader loader;
    PwVmRegion region;
    /* The loader requires a valid provider even when no module owns a span;
     * nothing here opens or closes anything through it. */
    const PwFileProvider provider = {
        .context = NULL, .open = unused_open, .close = unused_close,
        .open_namespace = NULL,
    };

    memset(&loader, 0, sizeof(loader));
    assert(pw_loader_init(&loader, &provider, wrapped) == PW_OK);
    assert(wrapped->reserve(wrapped->context, 0x1000u, wrapped->page_bytes,
                            &region) == PW_OK);
    assert(wrapped->commit(wrapped->context, &region, 0u, region.bytes,
                           PW_PROT_READ | PW_PROT_WRITE) == PW_OK);
    loader.modules[0].mapped.region = region;
    loader.modules[0].mapped_ok = 1u;
    loader.module_count = 1u;

    faults.releases = 0u;
    faults.fail_release = 1u;
    assert(pw_loader_release(&loader) == PW_ERR_VM);
    assert(loader.released_modules == 0u);
    assert(loader.module_count == 1u);          /* still ours */
    assert(loader.modules[0].mapped_ok == 1u);

    faults.fail_release = 0u;
    assert(pw_loader_release(&loader) == PW_OK);
    assert(loader.released_modules == 1u);
    assert(loader.module_count == 0u);
}

/* The engine's own region: a failed destroy keeps the engine initialized so
 * the caller can retry instead of leaking the arena. */
static void engine_region_test(const PwVmBackend *wrapped)
{
    static PwX86CacheEntry cache[4];
    PwX86Engine engine;

    memset(&engine, 0, sizeof(engine));
    assert(pw_x86_engine_init(&engine, wrapped, cache, 4u, 64u * 1024u, 1u,
                              unused_source, NULL) == PW_OK);
    faults.releases = 0u;
    faults.fail_release = 1u;
    assert(pw_x86_engine_destroy(&engine) != PW_OK);
    assert(engine.initialized);                 /* not forgotten */

    faults.fail_release = 0u;
    assert(pw_x86_engine_destroy(&engine) == PW_OK);
    assert(!engine.initialized);
}

int main(void)
{
    PwVmBackend real;
    PwVmBackend wrapped;

    assert(pw_vm_posix_backend(&real) == PW_OK);
    memset(&faults, 0, sizeof(faults));
    faults.real = &real;
    wrapped = wrap(&real);

    process_pages_test(&wrapped);
    loader_module_test(&wrapped);
    engine_region_test(&wrapped);
    return 0;
}
