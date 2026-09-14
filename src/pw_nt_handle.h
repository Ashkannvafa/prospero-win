/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The gate's typed NT handle table.
 *
 * One table carries every object a run hands the guest - files, directories,
 * registry keys, object-namespace directories and sections - because that is
 * what NT does: a handle names an object, not a service. Two properties are
 * the point of keeping it in one place.
 *
 * The first is that a value is issued once for the table's lifetime and then
 * never again. The contract is opacity, type and liveness - *not* secrecy: a
 * guest can guess, keep or forge a value, and what it gets back is either the
 * live object of the kind it asked for or STATUS_INVALID_HANDLE. A handle the
 * guest kept from an object that has since been released is refused instead of
 * silently naming whatever took its place, and because the issuer is
 * monotonic that stays true however many times a slot is reused: an earlier
 * design advanced a 16-value generation and handed the first value out again
 * on the seventeenth reuse, which the final review caught.
 *
 * The second is that a handle knows what it is. A handler asks for the kind it
 * expects and gets the real kind back, so a file can be told apart from a
 * directory and a key, and the wrong use is a refused call rather than a
 * misread object.
 */
#ifndef PROSPERO_WIN_PW_NT_HANDLE_H
#define PROSPERO_WIN_PW_NT_HANDLE_H

#include "../include/prospero_win.h"

enum {
    PW_NT_HANDLE_MAX = 16,
    PW_NT_HANDLE_PATH_MAX = 160,
    /* The first value a table ever issues. Values grow from here, so a run
     * that exhausts 32 bits stops issuing (PW_ERR_LIMIT) instead of wrapping
     * and resurrecting an old handle. */
    PW_NT_HANDLE_BASE = 0x100,
};

enum PwNtHandleKind {
    PW_NT_HANDLE_NONE = 0,
    PW_NT_HANDLE_FILE = 1,
    PW_NT_HANDLE_DIRECTORY = 2,
    PW_NT_HANDLE_KEY = 3,
    PW_NT_HANDLE_OBJECT_DIRECTORY = 4,
    PW_NT_HANDLE_SECTION = 5,
};

/* What a handle names. The token belongs to whichever service opened it. */
typedef struct PwNtObject {
    void *token;
    uint64_t size;                  /* file: bytes */
    uint64_t offset;                /* file: read position */
    char path[PW_NT_HANDLE_PATH_MAX + 1];   /* key/object: canonical path */
    /* file: which root the name belongs to, so a later re-open asks for the
     * same file rather than one that happens to share its name. */
    uint8_t file_namespace;
} PwNtObject;

typedef struct PwNtHandleTable {
    struct PwNtHandleSlot {
        PwNtObject object;
        uint32_t value;             /* the value issued for this occupancy */
        uint8_t kind;
        uint8_t used;
    } slots[PW_NT_HANDLE_MAX];
    uint32_t next_value;            /* the next value to issue; monotonic */
    uint32_t live;
    uint8_t exhausted;              /* the value space is used up for good */
} PwNtHandleTable;

void pw_nt_handle_init(PwNtHandleTable *table);

/* Takes the first free slot. Returns PW_ERR_LIMIT when the table is full. */
int pw_nt_handle_alloc(PwNtHandleTable *table, unsigned kind,
                       const PwNtObject *object, uint32_t *value);

/*
 * Resolves a guest value. On success *object points at the live object (pass
 * NULL when only the kind is needed) and *kind carries what it really is.
 * A value that is not a live handle of this table is PW_ERR_NOT_FOUND, which
 * is what handlers answer as STATUS_INVALID_HANDLE.
 */
int pw_nt_handle_lookup(PwNtHandleTable *table, uint32_t value,
                        PwNtObject **object, unsigned *kind);

/*
 * The value a live slot currently carries, or 0 when the slot is free. The
 * cleanup sweep uses it to release what the guest still holds.
 */
uint32_t pw_nt_handle_value_of(const PwNtHandleTable *table, uint32_t slot);

/*
 * Releases a handle and copies what it named into *released, so the caller can
 * close the service token it owns. The value is retired for good: the slot may
 * be reused, but that value can never be resolved again.
 */
int pw_nt_handle_release(PwNtHandleTable *table, uint32_t value,
                         PwNtObject *released, unsigned *kind);

/* True when the table has issued every value it ever can. */
int pw_nt_handle_exhausted(const PwNtHandleTable *table);

#endif /* PROSPERO_WIN_PW_NT_HANDLE_H */
