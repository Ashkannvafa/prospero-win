#include "../src/pw_vm_posix.h"

#include <assert.h>
#include <string.h>

static void test_backend_validation(void)
{
    PwVmBackend backend;

    assert(pw_vm_posix_backend(&backend) == PW_OK);
    assert(pw_vm_backend_valid(&backend));
    assert(backend.page_bytes >= 4096u);
    assert((backend.capabilities & PW_VM_CAP_PROTECT) != 0u);
    /* The POSIX backend runs code from the same alias it writes through. */
    assert((backend.capabilities & PW_VM_CAP_ALIASED_EXEC) == 0u);
    assert(!pw_vm_backend_valid(NULL));
    assert(pw_vm_posix_backend(NULL) == PW_ERR_PRECONDITION);

    PwVmBackend broken = backend;
    broken.reserve = NULL;
    assert(!pw_vm_backend_valid(&broken));
    broken = backend;
    broken.page_bytes = 5000u;              /* not a power of two */
    assert(!pw_vm_backend_valid(&broken));
    broken = backend;
    broken.protect = NULL;
    assert(!pw_vm_backend_valid(&broken));
}

static void test_reserve_alignment_and_release(void)
{
    PwVmBackend backend;
    PwVmRegion region;

    assert(pw_vm_posix_backend(&backend) == PW_OK);
    assert(backend.reserve(backend.context, 0x8000u, 0x10000u, &region) ==
           PW_OK);
    assert(region.write_base != NULL);
    assert(region.exec_base == region.write_base);
    assert(region.bytes == 0x8000u);
    assert(((uintptr_t)region.write_base & 0xffffu) == 0u);
    assert(backend.release(backend.context, &region) == PW_OK);
    assert(region.write_base == NULL);

    assert(backend.reserve(backend.context, 0u, 0x1000u, &region) ==
           PW_ERR_PRECONDITION);
    assert(backend.reserve(backend.context, 0x1000u, 3u, &region) ==
           PW_ERR_PRECONDITION);
    assert(backend.reserve(backend.context, 0x1000u, 0x1000u, NULL) ==
           PW_ERR_PRECONDITION);
    assert(backend.release(backend.context, NULL) == PW_ERR_PRECONDITION);
}

static void test_commit_and_protect(void)
{
    PwVmBackend backend;
    PwVmRegion region;
    volatile uint8_t *bytes;

    assert(pw_vm_posix_backend(&backend) == PW_OK);
    assert(backend.reserve(backend.context, 0x4000u, 0x1000u, &region) ==
           PW_OK);
    assert(backend.commit(backend.context, &region, 0u, 0x4000u,
                          PW_PROT_READ | PW_PROT_WRITE) == PW_OK);
    bytes = region.write_base;
    bytes[0] = 0x5au;
    bytes[0x3fffu] = 0xa5u;
    assert(bytes[0] == 0x5au && bytes[0x3fffu] == 0xa5u);

    /* Read-only afterwards; the bytes stay legible. */
    assert(backend.protect(backend.context, &region, 0u, 0x1000u,
                           PW_PROT_READ) == PW_OK);
    assert(bytes[0] == 0x5au);

    /* Ranges are bounded and page aligned by contract. */
    assert(backend.commit(backend.context, &region, 0u, 0x5000u,
                          PW_PROT_READ) == PW_ERR_PRECONDITION);
    assert(backend.commit(backend.context, &region, 0x100u, 0x1000u,
                          PW_PROT_READ) == PW_ERR_PRECONDITION);
    assert(backend.commit(backend.context, &region, 0u, 0u, PW_PROT_READ) ==
           PW_OK);
    assert(backend.release(backend.context, &region) == PW_OK);
}

static void test_region_bounds(void)
{
    PwVmRegion region;

    memset(&region, 0, sizeof(region));
    assert(!pw_vm_region_contains(&region, 0u, 1u));
    assert(!pw_vm_region_contains(NULL, 0u, 1u));

    region.write_base = (void *)0x1000;
    region.bytes = 0x2000u;
    assert(pw_vm_region_contains(&region, 0u, 0x2000u));
    assert(pw_vm_region_contains(&region, 0x1fffu, 1u));
    assert(!pw_vm_region_contains(&region, 0x2000u, 1u));
    assert(!pw_vm_region_contains(&region, 0u, 0x2001u));
    /* An offset near SIZE_MAX must not wrap into range. */
    assert(!pw_vm_region_contains(&region, (size_t)-1, 2u));
}

int main(void)
{
    test_backend_validation();
    test_reserve_alignment_and_release();
    test_commit_and_protect();
    test_region_bounds();
    return 0;
}
