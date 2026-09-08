#include "pw_compat32_ps5.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

extern int sysarch(int number, void *args);

enum {
    PW_I386_SET_LDT = 1,            /* <x86/sysarch.h> I386_SET_LDT */
    PW_LDT_AUTO_ALLOC = 0xffffffff, /* let the kernel choose the index */
};

/*
 * FreeBSD's amd64 `struct i386_ldt_args` packs the descriptor pointer, so
 * it sits at offset 4 rather than 8. Getting that wrong would hand the
 * kernel a garbage pointer, so the layout is asserted rather than assumed.
 */
struct pw_ldt_args {
    uint32_t start;
    uint64_t descs __attribute__((packed));
    uint32_t num;
};

_Static_assert(sizeof(struct pw_ldt_args) == 16,
               "i386_ldt_args must be 16 bytes on amd64");
_Static_assert(offsetof(struct pw_ldt_args, descs) == 4,
               "the descriptor pointer is packed at offset 4");
_Static_assert(offsetof(struct pw_ldt_args, num) == 12,
               "the descriptor count follows the packed pointer");

/*
 * Candidate addresses for the low pages. A title's own mappings normally
 * land high, and every far pointer in the stub carries a 32-bit offset, so
 * the address has to be requested explicitly. Several are tried because
 * which parts of the low address space a title may claim is unmeasured.
 */
static const uint32_t candidate_bases[] = {
    0x20000000u, 0x30000000u, 0x40000000u, 0x10000000u, 0x50000000u,
};

static int install(void *context, uint64_t code_descriptor,
                   uint64_t data_descriptor, uint32_t *index_out,
                   int *os_errno)
{
    PwCompat32Ps5 *state = context;
    uint64_t descriptors[2];
    struct pw_ldt_args args;
    int result;

    if (!state || !index_out || !os_errno)
        return PW_ERR_PRECONDITION;
    descriptors[0] = code_descriptor;
    descriptors[1] = data_descriptor;

    memset(&args, 0, sizeof(args));
    args.start = PW_LDT_AUTO_ALLOC;
    args.descs = (uint64_t)(uintptr_t)descriptors;
    args.num = 2u;

    errno = 0;
    result = sysarch(PW_I386_SET_LDT, &args);
    *os_errno = errno;
    state->last_errno = errno;
    if (result < 0)
        return PW_ERR_UNSUPPORTED;
    *index_out = (uint32_t)result;
    return PW_OK;
}

static void *map_fixed(uint32_t base, int protection)
{
    void *page = mmap((void *)(uintptr_t)base, PW_COMPAT32_PAGE_BYTES,
                      protection, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                      -1, 0);

    if (page == MAP_FAILED)
        return NULL;
    if ((uintptr_t)page != (uintptr_t)base) {
        /* MAP_FIXED was ignored: the address is unusable for 32-bit code. */
        (void)munmap(page, PW_COMPAT32_PAGE_BYTES);
        return NULL;
    }
    return page;
}

static int reserve_low(void *context, void **code_out, uint32_t *code_base,
                       void **data_out, uint32_t *data_base)
{
    PwCompat32Ps5 *state = context;
    const uint32_t count =
        (uint32_t)(sizeof(candidate_bases) / sizeof(candidate_bases[0]));

    if (!state || !code_out || !code_base || !data_out || !data_base)
        return PW_ERR_PRECONDITION;

    for (uint32_t index = 0; index < count; ++index) {
        const uint32_t base = candidate_bases[index];
        void *code;
        void *data;

        ++state->attempted_bases;
        /* Writable first; it is sealed executable once the stub is written. */
        code = map_fixed(base, PROT_READ | PROT_WRITE);
        if (!code) {
            state->last_errno = errno;
            continue;
        }
        data = map_fixed(base + PW_COMPAT32_PAGE_BYTES,
                         PROT_READ | PROT_WRITE);
        if (!data) {
            state->last_errno = errno;
            (void)munmap(code, PW_COMPAT32_PAGE_BYTES);
            continue;
        }
        state->chosen_base = base;
        *code_out = code;
        *code_base = base;
        *data_out = data;
        *data_base = base + PW_COMPAT32_PAGE_BYTES;
        return PW_OK;
    }
    return PW_ERR_VM;
}

static int seal_code(void *context, void *code_page, int *os_errno)
{
    PwCompat32Ps5 *state = context;

    if (!code_page || !os_errno)
        return PW_ERR_PRECONDITION;
    errno = 0;
    if (mprotect(code_page, PW_COMPAT32_PAGE_BYTES,
                 PROT_READ | PROT_EXEC) != 0) {
        *os_errno = errno;
        if (state)
            state->last_errno = errno;
        /*
         * No read-write to read-execute transition here. Reaching this
         * point means the gate needs the jitshm double mapping from gate
         * 0.2b before the transfer can be attempted at all.
         */
        return PW_ERR_VM;
    }
    *os_errno = 0;
    return PW_OK;
}

static void release_low(void *context, void *code_page, void *data_page)
{
    (void)context;
    if (code_page)
        (void)munmap(code_page, PW_COMPAT32_PAGE_BYTES);
    if (data_page)
        (void)munmap(data_page, PW_COMPAT32_PAGE_BYTES);
}

int pw_compat32_ps5_platform(PwCompat32Ps5 *state,
                             PwCompat32Platform *platform)
{
    if (!state || !platform)
        return PW_ERR_PRECONDITION;
    memset(state, 0, sizeof(*state));
    memset(platform, 0, sizeof(*platform));
    platform->context = state;
    platform->install = install;
    platform->reserve_low = reserve_low;
    platform->release_low = release_low;
    platform->seal_code = seal_code;
    return PW_OK;
}
