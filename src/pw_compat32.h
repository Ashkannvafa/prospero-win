/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Gate 0.2a: does this firmware let a title enter 32-bit compatibility
 * mode?
 *
 * The answer decides prospero-win's architecture. If a 32-bit code
 * descriptor can be installed and entered, classic 32-bit games run through
 * WoW64-style ABI thunking: their own opcodes execute on Zen 2 and only
 * arguments are translated at API boundaries, with zero instruction
 * emulation. If not, reaching them needs JIT recompilation instead, which
 * is a different project.
 *
 * The probe is deliberately two-staged. Installing the descriptor carries
 * no risk and is informative on its own, so it is reported before anything
 * is executed; the far transfer is attempted only when asked for. A run
 * that installs the descriptor and then dies still tells the operator which
 * of the two halves failed.
 *
 * Everything here is architecture-specific but not platform-specific: the
 * host test runs the same builder and the same transfer the console will,
 * and only descriptor installation and low-memory reservation are injected.
 */
#ifndef PROSPERO_WIN_COMPAT32_H
#define PROSPERO_WIN_COMPAT32_H

#include "pw_segment.h"

/*
 * Two pages, both below 2 GiB, and deliberately separate.
 *
 * 32-bit code addresses them with 32-bit operands and the far pointer back
 * into 64-bit mode carries a 32-bit offset, so neither may sit high. They
 * are split because the stub writes while it runs — saved registers, the
 * result slots and its own stack — and a page that is writable and
 * executable at once is exactly what this firmware makes hard to obtain.
 * Keeping code executable and data writable means the probe needs only two
 * ordinary mappings, and it keeps W^X intact for the thunk that grows out
 * of this.
 */
enum {
    PW_COMPAT32_PAGE_BYTES = 0x1000,
    /* Executable page. */
    PW_COMPAT32_OFF_LAUNCH64 = 0x000,   /* 64-bit: save state, enter 32-bit */
    PW_COMPAT32_OFF_ENTRY32 = 0x040,    /* 32-bit: prove the mode, go back  */
    PW_COMPAT32_OFF_LAND64 = 0x080,     /* 64-bit: restore state, return    */
    /* Writable page. */
    PW_COMPAT32_OFF_FAR_BACK = 0x000,   /* m16:32 to the 64-bit landing     */
    PW_COMPAT32_OFF_FAR_IN = 0x010,     /* m16:32 to the 32-bit entry       */
    PW_COMPAT32_OFF_SAVED_RET = 0x020,
    PW_COMPAT32_OFF_SAVED_RSP = 0x028,
    PW_COMPAT32_OFF_SAVED_RBP = 0x030,
    PW_COMPAT32_OFF_RESULT = 0x038,
    PW_COMPAT32_OFF_CS_SEEN = 0x03c,
    PW_COMPAT32_OFF_STACK32 = 0xf00,    /* top of the 32-bit stack          */
    /*
     * Three 0x40 bytes are `inc eax` in 32-bit mode and REX prefixes in
     * 64-bit mode, so this value can only be produced by a CPU that really
     * decoded the stub as 32-bit code.
     */
    PW_COMPAT32_EXPECTED_RESULT = 3u,
    PW_COMPAT32_RESULT_SEED = 0xffffffffu,
};

typedef struct PwCompat32Layout {
    uint32_t code_base;         /* executable page, strictly below 2 GiB */
    uint32_t data_base;         /* writable page, strictly below 2 GiB   */
    uint16_t code_selector;     /* the installed 32-bit code selector */
    uint16_t data_selector;     /* the installed 32-bit data selector */
    uint16_t cs64;              /* the caller's 64-bit code selector  */
    uint16_t ds64;              /* the caller's data selector         */
} PwCompat32Layout;

typedef struct PwCompat32Platform {
    void *context;
    /*
     * Asks the kernel to install both descriptors and reports the index of
     * each. They are reported separately because a kernel that allocates
     * indices on demand does so one descriptor at a time and need not
     * return adjacent slots. Returns PW_OK, or an error with *os_errno set.
     */
    int (*install)(void *context, uint64_t code_descriptor,
                   uint64_t data_descriptor, uint32_t *code_index_out,
                   uint32_t *data_index_out, int *os_errno);
    /*
     * Reserves one executable and one writable page, both below 2 GiB.
     * They may be the same mapping when the platform allows it; the report
     * records which addresses were handed out either way.
     */
    int (*reserve_low)(void *context, void **code_out, uint32_t *code_base,
                       void **data_out, uint32_t *data_base);
    void (*release_low)(void *context, void *code_page, void *data_page);
    /*
     * Optional. Called after the stub is written and before it runs, to
     * make the code page executable. Platforms that cannot hand out memory
     * that is writable and executable at once need this; on the console
     * that is the normal case, so the probe never relies on RWX.
     */
    int (*seal_code)(void *context, void *code_page, int *os_errno);
} PwCompat32Platform;

typedef struct PwCompat32Report {
    int install_result;
    int install_errno;
    int reserve_result;
    int build_result;
    int seal_result;
    int seal_errno;
    int transfer_result;
    uint32_t ldt_code_index;
    uint32_t ldt_data_index;
    uint16_t code_selector;
    uint16_t data_selector;
    uint16_t cs64;
    uint16_t ds64;
    uint32_t code_base;
    uint32_t data_base;
    uint32_t result_value;      /* PW_COMPAT32_EXPECTED_RESULT when genuine */
    uint32_t cs_seen;           /* CS observed from inside 32-bit mode */
    uint8_t transfer_attempted;
    uint8_t transfer_returned;
    uint8_t compat32_proven;
} PwCompat32Report;

/* Writes the transfer stub. Pure: no syscalls, no execution. */
int pw_compat32_build(void *code_page, void *data_page,
                      const PwCompat32Layout *layout);

/*
 * Performs the round trip. Returns PW_OK when control came back; the
 * caller still has to check the result value to know whether the CPU was
 * genuinely in 32-bit mode. PW_ERR_UNSUPPORTED on a non-x86-64 build.
 */
int pw_compat32_enter(void *data_page, const PwCompat32Layout *layout);

/*
 * Installs, builds, optionally transfers, and fills the report. The report
 * is filled on every path, including refusal.
 */
int pw_compat32_probe(const PwCompat32Platform *platform,
                      int attempt_transfer, PwCompat32Report *report);

/* Reads the caller's current cs and ds. */
void pw_compat32_current_selectors(uint16_t *cs, uint16_t *ds);

#endif
