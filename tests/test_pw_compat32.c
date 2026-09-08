/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Gate 0.2a contracts.
 *
 * The stub layout and encodings are pinned byte for byte, unconditionally.
 * On an x86-64 Linux host the probe is then run for real: the same builder
 * and the same transfer that will run on the console, with only descriptor
 * installation and low-memory reservation swapped for the host's. That
 * round trip is performed in a forked child, so a fault reports itself
 * instead of taking the whole suite down.
 */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1          /* syscall(2) under -std=c11 on glibc */
#endif

#include "../src/pw_compat32.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#if defined(__linux__) && defined(__x86_64__)
#define PW_HAVE_LIVE_PROBE 1
#include <asm/ldt.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#else
#define PW_HAVE_LIVE_PROBE 0
#endif

#define CODE_BASE 0x20000000u
#define DATA_BASE 0x20001000u

static uint8_t page[PW_COMPAT32_PAGE_BYTES];
static uint8_t data[PW_COMPAT32_PAGE_BYTES];

static uint32_t read_u32(const uint8_t *bytes, uint32_t offset)
{
    uint32_t value;

    memcpy(&value, bytes + offset, sizeof(value));
    return value;
}

static uint16_t read_u16(const uint8_t *bytes, uint32_t offset)
{
    uint16_t value;

    memcpy(&value, bytes + offset, sizeof(value));
    return value;
}

static PwCompat32Layout sample_layout(void)
{
    PwCompat32Layout layout;

    memset(&layout, 0, sizeof(layout));
    layout.code_base = CODE_BASE;
    layout.data_base = DATA_BASE;
    layout.code_selector = 0x0007u;
    layout.data_selector = 0x000fu;
    layout.cs64 = 0x0033u;
    layout.ds64 = 0x0000u;
    return layout;
}

static void test_builds_the_expected_stub(void)
{
    const PwCompat32Layout layout = sample_layout();

    assert(pw_compat32_build(page, data, &layout) == PW_OK);

    /* Launcher: save rsp/rbp, switch to the 32-bit stack, far jump in. */
    assert(memcmp(page + PW_COMPAT32_OFF_LAUNCH64,
                  "\x48\x89\x24\x25", 4) == 0);
    assert(read_u32(page, PW_COMPAT32_OFF_LAUNCH64 + 4) ==
           DATA_BASE + PW_COMPAT32_OFF_SAVED_RSP);
    assert(memcmp(page + PW_COMPAT32_OFF_LAUNCH64 + 8,
                  "\x48\x89\x2c\x25", 4) == 0);
    assert(read_u32(page, PW_COMPAT32_OFF_LAUNCH64 + 12) ==
           DATA_BASE + PW_COMPAT32_OFF_SAVED_RBP);
    assert(memcmp(page + PW_COMPAT32_OFF_LAUNCH64 + 16,
                  "\x48\xc7\xc4", 3) == 0);
    assert(read_u32(page, PW_COMPAT32_OFF_LAUNCH64 + 19) ==
           DATA_BASE + PW_COMPAT32_OFF_STACK32);
    /* ff /5 with a SIB absolute displacement: far indirect jump. */
    assert(memcmp(page + PW_COMPAT32_OFF_LAUNCH64 + 23,
                  "\xff\x2c\x25", 3) == 0);
    assert(read_u32(page, PW_COMPAT32_OFF_LAUNCH64 + 26) ==
           DATA_BASE + PW_COMPAT32_OFF_FAR_IN);

    /* 32-bit entry: DS first, then the mode proof. */
    assert(page[PW_COMPAT32_OFF_ENTRY32] == 0xb8);
    assert(read_u32(page, PW_COMPAT32_OFF_ENTRY32 + 1) == 0x000fu);
    assert(memcmp(page + PW_COMPAT32_OFF_ENTRY32 + 5, "\x8e\xd8", 2) == 0);
    assert(memcmp(page + PW_COMPAT32_OFF_ENTRY32 + 7, "\x31\xc0", 2) == 0);
    assert(memcmp(page + PW_COMPAT32_OFF_ENTRY32 + 9, "\x8c\xc8", 2) == 0);
    assert(page[PW_COMPAT32_OFF_ENTRY32 + 11] == 0xa3);
    assert(read_u32(page, PW_COMPAT32_OFF_ENTRY32 + 12) ==
           DATA_BASE + PW_COMPAT32_OFF_CS_SEEN);
    assert(page[PW_COMPAT32_OFF_ENTRY32 + 16] == 0xb8);
    assert(read_u32(page, PW_COMPAT32_OFF_ENTRY32 + 17) == 0u);
    /* The three bytes that only mean `inc eax` in 32-bit mode. */
    assert(page[PW_COMPAT32_OFF_ENTRY32 + 21] == 0x40);
    assert(page[PW_COMPAT32_OFF_ENTRY32 + 22] == 0x40);
    assert(page[PW_COMPAT32_OFF_ENTRY32 + 23] == 0x40);
    assert(page[PW_COMPAT32_OFF_ENTRY32 + 24] == 0xa3);
    assert(read_u32(page, PW_COMPAT32_OFF_ENTRY32 + 25) ==
           DATA_BASE + PW_COMPAT32_OFF_RESULT);
    /* ff /5 with mod=00 rm=101: absolute in 32-bit mode, not RIP-relative. */
    assert(memcmp(page + PW_COMPAT32_OFF_ENTRY32 + 29, "\xff\x2d", 2) == 0);
    assert(read_u32(page, PW_COMPAT32_OFF_ENTRY32 + 31) ==
           DATA_BASE + PW_COMPAT32_OFF_FAR_BACK);

    /* Landing: restore DS and the full 64-bit stack before returning. */
    assert(page[PW_COMPAT32_OFF_LAND64] == 0xb8);
    assert(read_u32(page, PW_COMPAT32_OFF_LAND64 + 1) == 0x0000u);
    assert(memcmp(page + PW_COMPAT32_OFF_LAND64 + 7,
                  "\x48\x8b\x24\x25", 4) == 0);
    assert(read_u32(page, PW_COMPAT32_OFF_LAND64 + 11) ==
           DATA_BASE + PW_COMPAT32_OFF_SAVED_RSP);
    assert(memcmp(page + PW_COMPAT32_OFF_LAND64 + 15,
                  "\x48\x8b\x2c\x25", 4) == 0);
    assert(memcmp(page + PW_COMPAT32_OFF_LAND64 + 23,
                  "\xff\x24\x25", 3) == 0);
    assert(read_u32(page, PW_COMPAT32_OFF_LAND64 + 26) ==
           DATA_BASE + PW_COMPAT32_OFF_SAVED_RET);

    /* Far pointers live in the writable page: offset then selector. */
    assert(read_u32(data, PW_COMPAT32_OFF_FAR_IN) ==
           CODE_BASE + PW_COMPAT32_OFF_ENTRY32);
    assert(read_u16(data, PW_COMPAT32_OFF_FAR_IN + 4) == 0x0007u);
    assert(read_u32(data, PW_COMPAT32_OFF_FAR_BACK) ==
           CODE_BASE + PW_COMPAT32_OFF_LAND64);
    assert(read_u16(data, PW_COMPAT32_OFF_FAR_BACK + 4) == 0x0033u);

    /* Seeded, so an unwritten slot cannot read as a pass. */
    assert(read_u32(data, PW_COMPAT32_OFF_RESULT) ==
           PW_COMPAT32_RESULT_SEED);
    assert(read_u32(data, PW_COMPAT32_OFF_CS_SEEN) ==
           PW_COMPAT32_RESULT_SEED);
    /* Nothing executable was written into the data page. */
    assert(data[PW_COMPAT32_OFF_STACK32 - 1] == 0x00);
    /* Unused space traps rather than falling through. */
    assert(page[PW_COMPAT32_OFF_LAND64 - 1] == 0xcc);
}

static void test_rejects_unusable_layouts(void)
{
    PwCompat32Layout layout = sample_layout();

    assert(pw_compat32_build(NULL, data, &layout) == PW_ERR_PRECONDITION);
    assert(pw_compat32_build(page, NULL, &layout) == PW_ERR_PRECONDITION);
    assert(pw_compat32_build(page, data, NULL) == PW_ERR_PRECONDITION);

    /* Above 2 GiB: `mov rsp, imm32` would sign-extend into nonsense. */
    layout.code_base = 0x80000000u;
    assert(pw_compat32_build(page, data, &layout) == PW_ERR_PRECONDITION);
    layout = sample_layout();
    layout.data_base = 0x80000000u;
    assert(pw_compat32_build(page, data, &layout) == PW_ERR_PRECONDITION);
    layout = sample_layout();
    layout.code_base = 0u;
    assert(pw_compat32_build(page, data, &layout) == PW_ERR_PRECONDITION);
    layout = sample_layout();
    layout.data_base = DATA_BASE + 1u;              /* unaligned */
    assert(pw_compat32_build(page, data, &layout) == PW_ERR_PRECONDITION);

    layout = sample_layout();
    layout.code_selector = 0u;
    assert(pw_compat32_build(page, data, &layout) == PW_ERR_PRECONDITION);
    layout = sample_layout();
    layout.cs64 = 0u;
    assert(pw_compat32_build(page, data, &layout) == PW_ERR_PRECONDITION);
}

static void test_probe_preconditions(void)
{
    PwCompat32Platform platform;
    PwCompat32Report report;

    memset(&platform, 0, sizeof(platform));
    assert(pw_compat32_probe(&platform, 0, NULL) == PW_ERR_PRECONDITION);
    assert(pw_compat32_probe(NULL, 0, &report) == PW_ERR_PRECONDITION);
    /* An incomplete platform is refused before anything is installed. */
    assert(pw_compat32_probe(&platform, 0, &report) == PW_ERR_PRECONDITION);
    assert(report.install_result == PW_ERR_PRECONDITION);
    assert(report.compat32_proven == 0u);
}

#if PW_HAVE_LIVE_PROBE

static int host_install(void *context, uint64_t code_descriptor,
                        uint64_t data_descriptor, uint32_t *code_index_out,
                        uint32_t *data_index_out, int *os_errno)
{
    struct user_desc desc;
    uint64_t installed = 0;
    uint8_t table[2 * sizeof(uint64_t)];

    (void)context;
    (void)data_descriptor;
    for (unsigned entry = 0; entry < 2u; ++entry) {
        memset(&desc, 0, sizeof(desc));
        desc.entry_number = entry;
        desc.base_addr = 0;
        desc.limit = PW_SEG_LIMIT_4GIB;
        desc.seg_32bit = 1;                 /* D/B set */
        desc.contents = entry == 0u ? 2u : 0u;   /* code, then data */
        desc.read_exec_only = 0;
        desc.limit_in_pages = 1;
        desc.seg_not_present = 0;
        desc.useable = 1;
        desc.lm = 0;                        /* L clear: compatibility mode */
        if (syscall(SYS_modify_ldt, 1, &desc, sizeof(desc)) != 0) {
            *os_errno = errno;
            return PW_ERR_UNSUPPORTED;
        }
    }

    /*
     * Read the descriptors back and compare against this project's own
     * encoder. The kernel and pw_segment_encode() must agree on the same
     * intent, apart from the AVL bit the host sets from `useable`.
     */
    if (syscall(SYS_modify_ldt, 0, table, sizeof(table)) ==
        (long)sizeof(table)) {
        const uint64_t avl = 1ull << 52;

        memcpy(&installed, table, sizeof(installed));
        assert((installed & ~avl) == (code_descriptor & ~avl));
        memcpy(&installed, table + sizeof(uint64_t), sizeof(installed));
        assert((installed & ~avl) == (pw_segment_compat32_data() & ~avl));
    }

    *code_index_out = 0u;
    *data_index_out = 1u;
    *os_errno = 0;
    return PW_OK;
}

/*
 * Two mappings, so the executable page never needs to be writable while it
 * runs. This is the shape the console needs too, where obtaining a page
 * that is writable and executable at once is the hard part.
 */
static int host_reserve_low(void *context, void **code_out,
                            uint32_t *code_base, void **data_out,
                            uint32_t *data_base)
{
    void *code;
    void *data_low;

    (void)context;
    code = mmap((void *)(uintptr_t)CODE_BASE, PW_COMPAT32_PAGE_BYTES,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (code == MAP_FAILED)
        return PW_ERR_VM;
    data_low = mmap((void *)(uintptr_t)DATA_BASE, PW_COMPAT32_PAGE_BYTES,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (data_low == MAP_FAILED) {
        (void)munmap(code, PW_COMPAT32_PAGE_BYTES);
        return PW_ERR_VM;
    }
    *code_out = code;
    *code_base = CODE_BASE;
    *data_out = data_low;
    *data_base = DATA_BASE;
    return PW_OK;
}

static int host_seal_code(void *context, void *code_page, int *os_errno)
{
    (void)context;
    if (mprotect(code_page, PW_COMPAT32_PAGE_BYTES,
                 PROT_READ | PROT_EXEC) != 0) {
        *os_errno = errno;
        return PW_ERR_VM;
    }
    return PW_OK;
}

static void host_release_low(void *context, void *code_page, void *data_page)
{
    (void)context;
    (void)munmap(code_page, PW_COMPAT32_PAGE_BYTES);
    (void)munmap(data_page, PW_COMPAT32_PAGE_BYTES);
}

/* Runs the real probe in a child so a fault is observable, not fatal. */
static void test_live_round_trip(void)
{
    PwCompat32Platform platform;
    PwCompat32Report *shared;
    pid_t child;
    int status = 0;

    shared = mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED) {
        (void)printf("  live probe skipped: no shared mapping\n");
        return;
    }
    memset(shared, 0, sizeof(*shared));

    memset(&platform, 0, sizeof(platform));
    platform.install = host_install;
    platform.reserve_low = host_reserve_low;
    platform.release_low = host_release_low;
    platform.seal_code = host_seal_code;

    child = fork();
    if (child == 0) {
        (void)pw_compat32_probe(&platform, 1, shared);
        _exit(0);
    }
    if (child < 0) {
        (void)printf("  live probe skipped: fork unavailable\n");
        return;
    }
    assert(waitpid(child, &status, 0) == child);

    if (shared->install_result != PW_OK) {
        /* The host refuses the descriptor: nothing to prove here. */
        (void)printf("  live probe skipped: modify_ldt refused (errno=%d)\n",
                     shared->install_errno);
        return;
    }

    /* Descriptors installed, so the transfer must have worked. */
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 0);
    assert(shared->reserve_result == PW_OK);
    assert(shared->build_result == PW_OK);
    /* The stub ran from a page that was not writable. */
    assert(shared->seal_result == PW_OK);
    assert(shared->transfer_attempted == 1u);
    assert(shared->transfer_returned == 1u);
    assert(shared->transfer_result == PW_OK);
    assert(shared->code_selector == 0x0007u);
    assert(shared->data_selector == 0x000fu);
    assert(shared->code_base == CODE_BASE);
    assert(shared->data_base == DATA_BASE);
    /* The decisive facts: 32-bit decoding, under our own selector. */
    assert(shared->result_value == PW_COMPAT32_EXPECTED_RESULT);
    assert(shared->cs_seen == shared->code_selector);
    assert(shared->compat32_proven == 1u);
    (void)printf("  live probe: entered compatibility mode under cs=0x%04x, "
                 "result=%u\n", shared->cs_seen, shared->result_value);
    (void)munmap(shared, sizeof(*shared));
}

#endif /* PW_HAVE_LIVE_PROBE */

int main(void)
{
    test_builds_the_expected_stub();
    test_rejects_unusable_layouts();
    test_probe_preconditions();
#if PW_HAVE_LIVE_PROBE
    test_live_round_trip();
#else
    (void)printf("  live probe unavailable on this platform\n");
#endif
    return 0;
}
