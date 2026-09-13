/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Export directory reader.
 *
 * Answers "which symbol does this module publish, at which RVA, and is it a
 * forwarder" from the unmapped file span. Nothing is bound, mapped or
 * executed here; the module-graph resolver in pw_export.c consumes this.
 *
 * Every table is bounds-checked against the file span before use and
 * forwarder strings are only recognised when their RVA lies inside the
 * export directory itself, which is what the PE format requires. A sparse
 * or out-of-range ordinal fails closed instead of resolving to whatever
 * happens to live at that slot.
 */
#ifndef PROSPERO_WIN_PE_EXPORT_H
#define PROSPERO_WIN_PE_EXPORT_H

#include "pe_image.h"

enum {
    PE_EXPORT_DIRECTORY_BYTES = 40u,
    PE_EXPORT_MAX_FUNCTIONS = 65536u,
    PE_EXPORT_MAX_NAMES = 65536u,
    PE_EXPORT_NAME_MAX = 255,
};

typedef struct PeExportDirectory {
    uint32_t directory_rva;
    uint32_t directory_size;        /* forwarder strings must live inside */
    char module_name[PE_EXPORT_NAME_MAX + 1];
    uint32_t module_name_rva;
    uint32_t ordinal_base;
    uint32_t function_count;
    uint32_t name_count;
    uint32_t functions_rva;
    uint32_t names_rva;
    uint32_t ordinals_rva;
} PeExportDirectory;

typedef struct PeExportSymbol {
    char name[PE_EXPORT_NAME_MAX + 1];      /* empty for an ordinal-only slot */
    char target[PE_EXPORT_NAME_MAX + 1];    /* forwarder target, empty otherwise */
    uint32_t rva;               /* callable/data RVA, or forwarder string RVA */
    uint32_t ordinal;           /* absolute ordinal (base + table index) */
    uint32_t index;             /* index inside the function table */
    uint32_t forwarder_rva;     /* 0 when this is not a forwarder */
    uint8_t by_ordinal;         /* the caller asked by ordinal */
    uint8_t is_forwarder;
    uint8_t is_code;            /* the RVA lies in an executable section */
} PeExportSymbol;

/*
 * Reads the directory header. An image without an export directory is not an
 * error: function_count and name_count are 0 and every lookup fails closed.
 */
int pe_export_parse(PeExportDirectory *directory, const PeImage *image);

/* Exact ASCII lookup by export name. Forwarder targets are not followed. */
int pe_export_find_name(const PeImage *image, const PeExportDirectory *directory,
                        const char *name, PeExportSymbol *out);

/* Lookup by absolute ordinal, filling the name when the table publishes one. */
int pe_export_find_ordinal(const PeImage *image,
                           const PeExportDirectory *directory,
                           uint32_t ordinal, PeExportSymbol *out);

/* One function-table slot. index must be below function_count. */
int pe_export_read_index(const PeImage *image,
                         const PeExportDirectory *directory, uint32_t index,
                         PeExportSymbol *out);

#endif
