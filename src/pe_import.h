/*
 * Import directory reader.
 *
 * Gate 1 answers only "which modules does this image need, and by which
 * names or ordinals". Nothing is bound: writing thunks belongs to the Win32
 * surface, which arrives once the module graph is proven.
 *
 * The tables are read from the unmapped file span so the loader can decide
 * whether a dependency is resolvable before it reserves memory for it.
 */
#ifndef PROSPERO_WIN_PE_IMPORT_H
#define PROSPERO_WIN_PE_IMPORT_H

#include "pe_image.h"

enum {
    PE_IMPORT_DESCRIPTOR_BYTES = 20u,
    PE_IMPORT_MAX_MODULES = 64,
    PE_IMPORT_NAME_MAX = 127,
    PE_IMPORT_MAX_SYMBOLS = 8192,
};

typedef struct PeImportModule {
    char name[PW_MODULE_NAME_MAX + 1];
    uint32_t name_rva;
    uint32_t lookup_table_rva;      /* OriginalFirstThunk; 0 when absent */
    uint32_t address_table_rva;     /* FirstThunk */
    uint32_t forwarder_chain;
    uint32_t timestamp;
    uint32_t named_count;
    uint32_t ordinal_count;
    uint8_t bound;                  /* a bound image needs its own handling */
} PeImportModule;

typedef struct PeImportTable {
    uint32_t module_count;
    uint32_t symbol_count;
    PeImportModule modules[PE_IMPORT_MAX_MODULES];
} PeImportTable;

typedef struct PeImportSymbol {
    char name[PE_IMPORT_NAME_MAX + 1];
    uint32_t thunk_rva;             /* slot in the address table */
    uint16_t hint;
    uint16_t ordinal;
    uint8_t by_ordinal;
} PeImportSymbol;

/*
 * Enumerates descriptors and counts each module's named and ordinal
 * imports. An empty or absent directory is not an error: module_count is 0.
 */
int pe_import_parse(PeImportTable *table, const PeImage *image);

/* Materialises one module's symbols; PW_ERR_LIMIT when capacity is short. */
int pe_import_enumerate(const PeImage *image, const PeImportModule *module,
                        PeImportSymbol *out, uint32_t capacity,
                        uint32_t *count);

#endif
