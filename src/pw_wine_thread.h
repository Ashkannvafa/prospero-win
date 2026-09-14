/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The threads this run models, and the two questions the loader asks about
 * them.
 *
 * AllocTlsSlot (dlls/ntdll/loader.c:1331) gives every module with a TLS
 * directory a slot, and for every thread of the process it then pokes that
 * thread's TLS block - so a process that loads a DLL with a TLS directory
 * walks its own thread list first, with NtGetNextThread, and asks each thread
 * where its TEB is with NtQueryInformationThread(ThreadBasicInformation).
 * This run models exactly one thread: the one it started, which is the only
 * thread a single-threaded process has. The list is a table rather than a
 * constant so that the thread support of the next tranche has somewhere to
 * put its second thread.
 */
#ifndef PROSPERO_WIN_PW_WINE_THREAD_H
#define PROSPERO_WIN_PW_WINE_THREAD_H

#include "pw_nt_dispatch.h"
#include "pw_guest_process.h"

struct PwWineCallContext;

enum {
    PW_WINE_THREAD_MAX = 4,
    /* THREAD_BASIC_INFORMATION as an i386 guest lays it out: ExitStatus,
     * TebBaseAddress, ClientId (process, thread), AffinityMask, Priority,
     * BasePriority. */
    PW_WINE_THREAD_BASIC_BYTES = 28u,
    /* The access bits this run can honour on a thread handle. */
    PW_WINE_THREAD_QUERY = 0x0040u,          /* THREAD_QUERY_INFORMATION */
    PW_WINE_THREAD_QUERY_LIMITED = 0x0800u,  /* ..._QUERY_LIMITED_INFORMATION */
    /* The state of a thread that is running: Wine's server answers
     * STATUS_PENDING for a thread that has not exited (server/thread.c:1819). */
    PW_WINE_THREAD_RUNNING = 0x00000103u,
    /* This run models one thread of a normal-priority process: Priority is the
     * dynamic delta, BasePriority the base it runs at. */
    PW_WINE_THREAD_AFFINITY = 1u,
    PW_WINE_THREAD_PRIORITY = 0u,
    PW_WINE_THREAD_BASE_PRIORITY = 8u,
};

/*
 * The i386 register context, which is how a thread's state travels: the
 * kernel builds one at the top of a thread's initial stack and ntdll's
 * initialization entry receives it as its first argument
 * (dlls/ntdll/unix/signal_i386.c:2455-2506), and NtContinue is what installs
 * one to resume a thread. The offsets are the documented NT ones
 * (`winnt.h`'s I386_CONTEXT: 0x2cc bytes, Eax at 0xb0, the floating-point save
 * area at 0x1c with its register area at 0x34, and the 512-byte
 * ExtendedRegisters blob at 0xcc, whose XSAVE_FORMAT shape puts MxCsr at
 * 0x18).
 */
enum {
    PW_WINE_CONTEXT_BYTES = 0x2ccu,
    PW_WINE_CONTEXT_OFFSET_FLAGS = 0x00u,
    PW_WINE_CONTEXT_OFFSET_FLOAT_CONTROL = 0x1cu,
    PW_WINE_CONTEXT_OFFSET_SEG_GS = 0x8cu,
    PW_WINE_CONTEXT_OFFSET_SEG_FS = 0x90u,
    PW_WINE_CONTEXT_OFFSET_EDI = 0x9cu,
    PW_WINE_CONTEXT_OFFSET_ESI = 0xa0u,
    PW_WINE_CONTEXT_OFFSET_EBX = 0xa4u,
    PW_WINE_CONTEXT_OFFSET_EDX = 0xa8u,
    PW_WINE_CONTEXT_OFFSET_ECX = 0xacu,
    PW_WINE_CONTEXT_OFFSET_EAX = 0xb0u,
    PW_WINE_CONTEXT_OFFSET_EBP = 0xb4u,
    PW_WINE_CONTEXT_OFFSET_EIP = 0xb8u,
    PW_WINE_CONTEXT_OFFSET_SEG_CS = 0xbcu,
    PW_WINE_CONTEXT_OFFSET_EFLAGS = 0xc0u,
    PW_WINE_CONTEXT_OFFSET_ESP = 0xc4u,
    PW_WINE_CONTEXT_OFFSET_SEG_SS = 0xc8u,
    PW_WINE_CONTEXT_OFFSET_EXTENDED_CONTROL = 0xccu,
    PW_WINE_CONTEXT_OFFSET_EXTENDED_MXCSR = 0xe4u,
    /* The three groups the kernel's own initial context asks for. */
    PW_WINE_CONTEXT_FLAG_CONTROL = 0x00000001u,
    PW_WINE_CONTEXT_FLAG_INTEGER = 0x00000002u,
    PW_WINE_CONTEXT_FLAG_SEGMENTS = 0x00000004u,
    PW_WINE_CONTEXT_FLAG_i386 = 0x00010000u,
    /* What the kernel fills the initial context's ContextFlags with:
     * CONTEXT_FULL (control, integer, segments) plus the floating-point and
     * extended-register groups (dlls/ntdll/unix/signal_i386.c:2493). */
    PW_WINE_CONTEXT_FLAGS_INITIAL = 0x0001002fu,
    /* The user code and stack segments this run publishes, and the flags word
     * the kernel gives a fresh thread. */
    PW_WINE_CONTEXT_USER_CS = 0x1bu,
    PW_WINE_CONTEXT_USER_SS = 0x23u,
    PW_WINE_CONTEXT_EFLAGS = 0x202u,
};

/* One thread of this run. */
typedef struct PwWineThread {
    uint32_t id;                    /* UniqueThread, as this run publishes it */
    uint32_t teb_base;
    uint8_t mine;                   /* the thread the run is executing on */
} PwWineThread;

/* The thread after `last`, with a handle to it; STATUS_NO_MORE_ENTRIES when
 * the list is exhausted. */
int pw_wine_thread_next(struct PwWineCallContext *calls,
                        const PwUnixCallFrame *frame, PwUnixCallAccess guest,
                        void *context, uint32_t *status,
                        uint32_t *argument_index);

/* ThreadBasicInformation for a thread handle this run owns. */
int pw_wine_thread_query(struct PwWineCallContext *calls,
                         const PwUnixCallFrame *frame, PwUnixCallAccess guest,
                         void *context, uint32_t *status,
                         uint32_t *argument_index);

/* NtContinue: install the state the guest's own context describes and resume
 * there instead of returning to the caller. */
int pw_wine_thread_continue(struct PwWineCallContext *calls,
                            const PwUnixCallFrame *frame,
                            PwUnixCallAccess guest, void *context,
                            uint32_t *status, uint32_t *argument_index);

#endif /* PROSPERO_WIN_PW_WINE_THREAD_H */
