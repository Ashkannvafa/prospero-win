/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * One registry entry per Unix call the bridge services.
 *
 * The gate used to dispatch with a switch, which meant the list of serviced
 * calls existed three times: as switch cases, as prose in the documentation
 * and as the numbers quoted in the evidence. This is the one source of truth
 * instead. A handler is a function with a uniform signature, and an entry also
 * records what the handler answers (the information classes it supports, 0
 * when it has none) and which self-contained test owns it, because those are
 * exactly the things that drift when a call is added.
 *
 * tests/test_nt_handler_ledger.py parses the table and cross-checks it against
 * the versioned call table in src/pw_unix_call.c and against the test files on
 * disk, so an entry that names a call nobody can reach, a name that disagrees
 * with the Wine revision or a test that does not exist fails the build.
 */
#ifndef PROSPERO_WIN_PW_NT_DISPATCH_H
#define PROSPERO_WIN_PW_NT_DISPATCH_H

#include "../include/prospero_win.h"
#include "pw_unix_call.h"
#include "pw_x86_block.h"

/* The gate's per-run state, defined by the gate: the registry only needs to
 * name it, because every handler already takes exactly this signature. */
struct PwWineCallContext;

/* One serviced call. The signature is the one every handler already has. */
typedef int (*PwNtHandlerFn)(struct PwWineCallContext *calls,
                             const PwUnixCallFrame *frame,
                             PwUnixCallAccess guest, void *context,
                             uint32_t *status, uint32_t *argument_index);

enum {
    /* How many information classes an entry may declare. */
    PW_NT_DISPATCH_MAX_CLASSES = 4,
};

typedef struct PwNtHandler {
    uint32_t id;                    /* the Wine i386 syscall number */
    /* The classes the handler answers, terminated by PW_NT_CLASS_NONE. */
    uint32_t classes[PW_NT_DISPATCH_MAX_CLASSES];
    const char *test;               /* the test that owns this handler */
    PwNtHandlerFn handle;
} PwNtHandler;

enum {
    PW_NT_CLASS_NONE = 0xffffffffu,
};

#endif /* PROSPERO_WIN_PW_NT_DISPATCH_H */
