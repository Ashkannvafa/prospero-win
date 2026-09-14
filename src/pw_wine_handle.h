/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The gate's side of the typed NT handle table.
 *
 * src/pw_nt_handle.c owns the table itself: opaque, generation-safe values and
 * a lookup that reports what a handle really is. This unit owns what the run
 * does around it, which is the same for every kind: allocating a handle also
 * publishes the live count in the evidence, releasing one also closes the
 * token the right service owns, and NtClose (one handler for every kind,
 * because NT has one) answers STATUS_INVALID_HANDLE for a value that is not a
 * live handle of this run.
 */
#ifndef PROSPERO_WIN_PW_WINE_HANDLE_H
#define PROSPERO_WIN_PW_WINE_HANDLE_H

#include "pw_nt_dispatch.h"
#include "pw_nt_handle.h"

struct PwWineCallContext;

/* Takes a handle for an object, and records the new live count. */
int pw_wine_handle_alloc(struct PwWineCallContext *calls,
                         const PwNtObject *object, unsigned kind,
                         uint32_t *value);

/* Resolves a guest value to the object and the kind it really names. */
int pw_wine_handle_lookup(struct PwWineCallContext *calls, uint32_t value,
                          PwNtObject **object, unsigned *kind);

/* Releases a handle and closes whatever the service behind it owns. */
int pw_wine_handle_release(struct PwWineCallContext *calls, uint32_t value);

/* What a handle names, built once at the call site. */
PwNtObject pw_wine_handle_object(void *token, uint64_t size, const char *path);

/* NtClose: the one handler every kind of handle shares. */
int pw_wine_handle_close(struct PwWineCallContext *calls,
                         const PwUnixCallFrame *frame,
                         PwUnixCallAccess guest, void *context,
                         uint32_t *status, uint32_t *argument_index);

#endif /* PROSPERO_WIN_PW_WINE_HANDLE_H */
