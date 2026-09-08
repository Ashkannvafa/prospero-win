/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_lowmem_ps5.h"

#include <errno.h>
#include <string.h>
#include <sys/mman.h>

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

#define PW_FOUR_GIB 0x100000000ull
#define PW_MIB (1024ull * 1024ull)

/* Where to ask. Clear of the title image, which sits at 0x400000. */
#define PW_LOW_HINT 0x10000000ull

int pw_lowmem_ps5_probe(PwLowMemReport *report)
{
    static const uint64_t sizes[] = {
        16ull * PW_MIB, 256ull * PW_MIB, 1024ull * PW_MIB,
        2048ull * PW_MIB, 3072ull * PW_MIB,
    };
    const uint32_t count = (uint32_t)(sizeof(sizes) / sizeof(sizes[0]));

    if (!report)
        return PW_ERR_PRECONDITION;
    memset(report, 0, sizeof(*report));
    report->mprotect_rx = -1;
    report->mprotect_rwx = -1;

    for (uint32_t index = 0; index < count && index < 8u; ++index) {
        PwLowMemResult *result = &report->results[index];
        void *got;

        result->requested_bytes = sizes[index];
        got = mmap((void *)(uintptr_t)PW_LOW_HINT, (size_t)sizes[index],
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        ++report->attempts;
        if (got == MAP_FAILED)
            continue;
        result->address = (uint64_t)(uintptr_t)got;
        result->honoured_hint = result->address == PW_LOW_HINT ? 1u : 0u;
        result->below_four_gib =
            result->address + sizes[index] <= PW_FOUR_GIB ? 1u : 0u;
        if (result->below_four_gib &&
            sizes[index] > report->largest_low_bytes) {
            report->largest_low_bytes = sizes[index];
            report->largest_low_base = result->address;
        }
        (void)munmap(got, (size_t)sizes[index]);
    }

    /* Usability, on a modest span so the check cannot fail for size alone. */
    {
        const size_t bytes = 1u * (size_t)PW_MIB;
        void *got = mmap((void *)(uintptr_t)PW_LOW_HINT, bytes,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (got != MAP_FAILED && (uint64_t)(uintptr_t)got < PW_FOUR_GIB) {
            volatile uint32_t *words = got;

            words[0] = 0xa5a5a5a5u;
            words[(bytes / 4u) - 1u] = 0x5a5a5a5au;
            report->write_read_ok = words[0] == 0xa5a5a5a5u &&
                words[(bytes / 4u) - 1u] == 0x5a5a5a5au;
            errno = 0;
            report->mprotect_rx =
                mprotect(got, bytes, PROT_READ | PROT_EXEC) == 0 ? 0 : errno;
            errno = 0;
            report->mprotect_rwx =
                mprotect(got, bytes,
                         PROT_READ | PROT_WRITE | PROT_EXEC) == 0 ? 0 : errno;
        }
        if (got != MAP_FAILED)
            (void)munmap(got, bytes);
    }
    return PW_OK;
}
