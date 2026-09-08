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
    PW_I386_GET_LDT = 0,            /* <x86/sysarch.h> I386_GET_LDT */
    PW_I386_SET_LDT = 1,            /* <x86/sysarch.h> I386_SET_LDT */
    PW_AMD64_GET_FSBASE = 128,      /* control: implemented everywhere */
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

/*
 * Installs exactly one descriptor and returns the index the kernel chose.
 *
 * FreeBSD's amd64 `amd64_set_ldt` honours `LDT_AUTO_ALLOC` only for a
 * single descriptor: ask for two in one call and it takes the range-check
 * path instead, where `start` of 0xffffffff is refused as EINVAL whatever
 * the kernel's policy is. An earlier version of this file did exactly that
 * and its EINVAL was briefly mistaken for a platform refusal.
 */
static int set_one(uint64_t descriptor, uint32_t *index_out, int *os_errno)
{
    struct pw_ldt_args args;
    uint64_t entry = descriptor;
    int result;

    memset(&args, 0, sizeof(args));
    args.start = PW_LDT_AUTO_ALLOC;
    args.descs = (uint64_t)(uintptr_t)&entry;
    args.num = 1u;

    errno = 0;
    result = sysarch(PW_I386_SET_LDT, &args);
    *os_errno = errno;
    if (result < 0)
        return PW_ERR_UNSUPPORTED;
    *index_out = (uint32_t)result;
    return PW_OK;
}

static int install(void *context, uint64_t code_descriptor,
                   uint64_t data_descriptor, uint32_t *code_index_out,
                   uint32_t *data_index_out, int *os_errno)
{
    PwCompat32Ps5 *state = context;
    int status;

    if (!state || !code_index_out || !data_index_out || !os_errno)
        return PW_ERR_PRECONDITION;

    status = set_one(code_descriptor, code_index_out, os_errno);
    state->last_errno = *os_errno;
    if (status != PW_OK)
        return status;
    status = set_one(data_descriptor, data_index_out, os_errno);
    state->last_errno = *os_errno;
    return status;
}

/*
 * Argument matrix. One EINVAL says nothing about whether the operation is
 * unavailable or the arguments were wrong, so every shape is tried and
 * reported separately, with a known-good `sysarch` operation as a control.
 */
int pw_compat32_ps5_diagnose(PwLdtAttempt *out, uint32_t capacity,
                             uint32_t *count)
{
    static const struct {
        const char *label;
        int op;
        uint32_t start;
        uint32_t num;
    } matrix[] = {
        {"get-num1", PW_I386_GET_LDT, 0u, 1u},
        {"set-auto-num1", PW_I386_SET_LDT, PW_LDT_AUTO_ALLOC, 1u},
        {"set-auto-num2", PW_I386_SET_LDT, PW_LDT_AUTO_ALLOC, 2u},
        {"set-start0-num1", PW_I386_SET_LDT, 0u, 1u},
        {"set-start1-num1", PW_I386_SET_LDT, 1u, 1u},
        {"get-num4", PW_I386_GET_LDT, 0u, 4u},
    };
    const uint32_t total =
        (uint32_t)(sizeof(matrix) / sizeof(matrix[0])) + 1u;
    uint64_t scratch[8];
    void *fsbase = NULL;
    uint32_t index = 0u;

    if (!out || !count || capacity < total)
        return PW_ERR_PRECONDITION;
    *count = 0u;

    /* Control: a sysarch operation every amd64 kernel implements. */
    scratch[0] = 0u;
    errno = 0;
    out[index].label = "control-getfsbase";
    out[index].op = PW_AMD64_GET_FSBASE;
    out[index].start = 0u;
    out[index].num = 0u;
    out[index].rc = sysarch(PW_AMD64_GET_FSBASE, &fsbase);
    out[index].os_errno = out[index].rc < 0 ? errno : 0;
    ++index;

    for (uint32_t entry = 0; entry < total - 1u; ++entry) {
        struct pw_ldt_args args;

        memset(scratch, 0, sizeof(scratch));
        scratch[0] = pw_segment_compat32_code();
        scratch[1] = pw_segment_compat32_data();
        memset(&args, 0, sizeof(args));
        args.start = matrix[entry].start;
        args.descs = (uint64_t)(uintptr_t)scratch;
        args.num = matrix[entry].num;

        errno = 0;
        out[index].label = matrix[entry].label;
        out[index].op = matrix[entry].op;
        out[index].start = matrix[entry].start;
        out[index].num = matrix[entry].num;
        out[index].rc = sysarch(matrix[entry].op, &args);
        out[index].os_errno = out[index].rc < 0 ? errno : 0;
        ++index;
    }
    *count = index;
    return PW_OK;
}

/*
 * Requests a page at a specific low address using a hint, never MAP_FIXED.
 *
 * Measured on FW 12.02: this kernel ignores MAP_EXCL, and a plain MAP_FIXED
 * silently replaces whatever is already mapped at the target — a live
 * mapping's contents were observed being overwritten. MAP_FIXED is
 * therefore unusable here without first proving the range is free. The hint
 * form cannot displace anything and is honoured exactly when the range is
 * available, so the address is simply verified afterwards.
 */
static void *map_low(uint32_t base, int protection)
{
    void *page = mmap((void *)(uintptr_t)base, PW_COMPAT32_PAGE_BYTES,
                      protection, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (page == MAP_FAILED)
        return NULL;
    if ((uintptr_t)page != (uintptr_t)base) {
        /* The hint was declined; that address is occupied or unusable. */
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
        code = map_low(base, PROT_READ | PROT_WRITE);
        if (!code) {
            state->last_errno = errno;
            continue;
        }
        data = map_low(base + PW_COMPAT32_PAGE_BYTES,
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
