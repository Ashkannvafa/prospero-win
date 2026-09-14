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

#endif /* PROSPERO_WIN_PW_WINE_THREAD_H */
