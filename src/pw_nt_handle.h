/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The gate's typed NT handle table.
 *
 * One table carries every object a run hands the guest - files, directories,
 * registry keys, object-namespace directories and sections - because that is
 * what NT does: a handle names an object, not a service. Two properties are
 * the point of keeping it in one place.
 *
 * The first is that the value is opaque and generation-safe. A guest value is
 * a base plus a slot plus a generation, so a handle the guest kept from a slot
 * that has since been released is refused instead of silently naming whatever
 * was allocated next, and a value the guest guessed names nothing.
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
    /* Slots and generations give the guest a value range of
     * PW_NT_HANDLE_BASE .. PW_NT_HANDLE_BASE + MAX*GENERATIONS - 1. */
    PW_NT_HANDLE_BASE = 0x100,
    PW_NT_HANDLE_GENERATIONS = 16,
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
} PwNtObject;

typedef struct PwNtHandleTable {
    struct PwNtHandleSlot {
        PwNtObject object;
        uint8_t kind;
        uint8_t generation;
        uint8_t used;
    } slots[PW_NT_HANDLE_MAX];
    uint32_t live;
} PwNtHandleTable;

void pw_nt_handle_init(PwNtHandleTable *table);

/* Takes the first free slot. Returns PW_ERR_LIMIT when the table is full. */
int pw_nt_handle_alloc(PwNtHandleTable *table, unsigned kind,
                       const PwNtObject *object, uint32_t *value);

/*
 * Resolves a guest value. On success *object points at the live object (pass
 * NULL when only the kind is needed) and *kind carries what it really is.
 * A value that is not a live handle of this generation is PW_ERR_NOT_FOUND,
 * which is what handlers answer as STATUS_INVALID_HANDLE.
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
 * close the service token it owns. The slot's generation advances, so the
 * released value can never be resolved again.
 */
int pw_nt_handle_release(PwNtHandleTable *table, uint32_t value,
                         PwNtObject *released, unsigned *kind);

#endif /* PROSPERO_WIN_PW_NT_HANDLE_H */
