/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Versioned Wine Unix-call table and bridge.
 *
 * Wine's i386 PE syscall stubs load a call number into EAX and jump through
 * __wine_syscall_dispatcher. The number is a position in a table that belongs
 * to one Wine revision, so the first thing a bridge needs is a table that is
 * explicitly versioned and checkable: `PwUnixCallInfo` carries the number, the
 * exported name and the stdcall argument width, and `tests/test_unix_call_table.py`
 * cross-checks every entry against the pinned Wine source when a checkout is
 * present.
 *
 * Nothing here dereferences a guest pointer by itself. `pw_unix_call_read`
 * copies the frame out of validated guest memory and reports which argument
 * slot failed, so a handler can only ever see values that the gate already
 * proved are inside a declared guest region.
 */
#ifndef PROSPERO_WIN_PW_UNIX_CALL_H
#define PROSPERO_WIN_PW_UNIX_CALL_H

#include "../include/prospero_win.h"
#include "pw_x86_block.h"

enum {
    PW_UNIX_CALL_NAME_MAX = 47,
    PW_UNIX_CALL_MAX_ARGS = 16,     /* 64 bytes: the widest i386 call */
    /* Real ntdll initialization reaches more calls than the first bridge
     * needed, and the transcript has to stay contiguous: a run that stops at
     * an unimplemented call must still be able to report every call before
     * it. */
    PW_UNIX_CALL_MAX_SEQUENCE = 32,
};

/* The Wine revision the table numbers are taken from. */
#define PW_UNIX_CALL_WINE_COMMIT "490f6d5dcbb2a5047345b8af88d114bbcaad69a8"

typedef struct PwUnixCallInfo {
    uint32_t id;
    const char *name;
    uint32_t arg_bytes;
} PwUnixCallInfo;

/*
 * The frame a Wine syscall stub leaves behind when its caller used a normal
 * call, which is the shape every Wine module uses:
 *
 *   [esp]     return address into the stub itself (the stub's own call)
 *   [esp+4]   the caller's return address
 *   [esp+8..] the stdcall arguments
 *
 * The two levels exist because the stub reaches the dispatcher with a call,
 * so the bridge returns to the caller with the stub's frame gone:
 * EIP = [esp+4] and ESP = esp + 8 + arg_bytes, which is what the stub's own
 * "ret imm16" would have produced. Every field is read from guest memory the
 * caller validated.
 */
typedef struct PwUnixCallFrame {
    uint32_t id;
    uint32_t stub_return_pc;        /* provenance: inside the issuing stub */
    uint32_t return_pc;             /* where the guest resumes */
    uint32_t arg_bytes;
    uint32_t args[PW_UNIX_CALL_MAX_ARGS];
    uint32_t esp;
} PwUnixCallFrame;

typedef enum PwUnixCallOutcome {
    PW_UNIX_CALL_HANDLED = 1,       /* serviced; the guest continues */
    PW_UNIX_CALL_UNIMPLEMENTED = 2, /* known number, no handler yet */
    PW_UNIX_CALL_UNKNOWN = 3,       /* number is not in this table */
    PW_UNIX_CALL_REJECTED = 4,      /* handler refused the arguments */
} PwUnixCallOutcome;

typedef struct PwUnixCallRecord {
    uint32_t id;
    uint32_t arg_bytes;
    uint32_t stub_return_pc;
    uint32_t return_pc;
    uint32_t status;                /* NTSTATUS when handled */
    uint32_t argument_index;        /* first rejected argument, when rejected */
    PwUnixCallOutcome outcome;
    char name[PW_UNIX_CALL_NAME_MAX + 1];
    uint32_t argument_count;        /* arguments actually read from the frame */
    uint32_t args[PW_UNIX_CALL_MAX_ARGS];
    uint32_t esp;
} PwUnixCallRecord;

static inline const PwX86Memory *pw_unix_call_regions(const PwX86State *state,
                                                      unsigned *count)
{
    if (count)
        *count = state ? state->memory_count : 0u;
    return state ? state->memory : NULL;
}

const PwUnixCallInfo *pw_unix_call_lookup(uint32_t id);

uint32_t pw_unix_call_table_count(void);

const PwUnixCallInfo *pw_unix_call_table_entry(uint32_t index);

/*
 * The accessor's direction follows the `write` flag: with write == 0 it
 * copies guest memory into the caller's buffer, with write != 0 it stores the
 * caller's buffer into guest memory after checking that the region is
 * writable. `pw_unix_call_read` only ever reads.
 *
 * Returns PW_OK, or PW_ERR_MALFORMED naming the failing argument through
 * *argument_index.
 */
typedef int (*PwUnixCallAccess)(void *context, uint32_t address,
                                void *bytes, uint32_t size, int write);

int pw_unix_call_read(const PwUnixCallInfo *info,
                      PwUnixCallAccess guest_access,
                      void *context, uint32_t esp, PwUnixCallFrame *frame,
                      uint32_t *argument_index);

/* Counts of the calls a run serviced, for the evidence record. */
typedef struct PwUnixCallTally {
    uint64_t handled;
    uint64_t unimplemented;
    uint64_t unknown;
    uint64_t rejected;
    uint32_t records;
    PwUnixCallRecord sequence[PW_UNIX_CALL_MAX_SEQUENCE];
} PwUnixCallTally;

void pw_unix_call_record(PwUnixCallTally *tally, const PwUnixCallFrame *frame,
                         const PwUnixCallInfo *info, uint32_t status,
                         uint32_t argument_index, PwUnixCallOutcome outcome);

const char *pw_unix_call_outcome_name(PwUnixCallOutcome outcome);

/* STATUS_SUCCESS and a few values a first bridge can legitimately return. */
enum {
    PW_NT_SUCCESS = 0x00000000u,
    PW_NT_INVALID_PARAMETER = 0xc000000du,
    PW_NT_INVALID_HANDLE = 0xc0000008u,
    PW_NT_NOT_IMPLEMENTED = 0xc0000002u,
    PW_NT_ACCESS_DENIED = 0xc0000022u,
    PW_NT_CONFLICTING_ADDRESSES = 0xc0000018u,
    /* What Wine answers when the address is not one of its own views, and what
     * its server answers when two views are not the same file
     * (dlls/ntdll/unix/virtual.c:6897 NtAreMappedFilesTheSame and
     * server/mapping.c:1779 is_same_mapping). */
    PW_NT_NOT_SAME_DEVICE = 0xc00000d4u,
    PW_NT_INVALID_ADDRESS = 0xc0000141u,
    PW_NT_OBJECT_NAME_NOT_FOUND = 0xc0000034u,
    PW_NT_END_OF_FILE = 0xc0000011u,
    PW_NT_INVALID_INFO_CLASS = 0xc0000003u,
    PW_NT_INFO_LENGTH_MISMATCH = 0xc0000004u,
    PW_NT_BUFFER_TOO_SMALL = 0xc0000023u,
    PW_NT_INVALID_DEVICE_REQUEST = 0xc0000010u,
    PW_NT_UNABLE_TO_FREE_VM = 0xc000001au,
    PW_NT_MEMORY_NOT_ALLOCATED = 0xc00000a0u,
    PW_NT_NOT_SUPPORTED = 0xc00000bbu,
    PW_NT_INVALID_IMAGE_FORMAT = 0xc000007bu,
    /* What Wine's own Unix loader answers when it cannot find a Unix library
     * (dlls/ntdll/unix/loader.c:862,987). */
    PW_NT_DLL_NOT_FOUND = 0xc0000135u,
    PW_NT_OBJECT_NAME_INVALID = 0xc0000033u,
    PW_NT_BUFFER_OVERFLOW = 0x80000005u,
    /* What Wine's server returns when a thread enumeration reaches the end of
     * its list (server/thread.c:2329 get_next_thread). */
    PW_NT_NO_MORE_ENTRIES = 0x8000001au,
    /* What Wine answers for the case map when it is asked with an id the
     * section has no name for (dlls/ntdll/unix/env.c:183). */
    PW_NT_UNSUCCESSFUL = 0xc0000001u,
};

#endif
