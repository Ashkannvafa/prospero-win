/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * PE32 TLS directory reader.
 *
 * The TLS directory is the one place in a PE image whose pointer fields are
 * guest virtual addresses rather than RVAs. Treating them as file offsets or
 * as host pointers is the classic way to "make TLS work" while mapping the
 * wrong bytes, so this parser converts every field explicitly, refuses
 * anything below the image base, and never returns a raw value the caller
 * could confuse for an offset.
 *
 * The template, the index slot and the callback array are all validated
 * against mapped file bytes with checked arithmetic before anything is
 * allocated, written or executed.
 */
#ifndef PROSPERO_WIN_PE_TLS_H
#define PROSPERO_WIN_PE_TLS_H

#include "pe_image.h"

enum {
    PE_TLS_DIRECTORY_BYTES = 24u,
    PE_TLS_MAX_CALLBACKS = 32u,
    PE_TLS_MAX_TEMPLATE = 1024u * 1024u,
    PE_TLS_MAX_ZERO_FILL = 1024u * 1024u,
};

typedef struct PeTlsCallback {
    uint32_t va;                    /* as stored in the image */
    uint32_t rva;
} PeTlsCallback;

typedef struct PeTlsDirectory {
    uint32_t directory_rva;
    uint32_t directory_size;
    uint32_t start_va;
    uint32_t end_va;
    uint32_t index_va;
    uint32_t callbacks_va;
    uint32_t zero_fill;
    uint32_t characteristics;
    uint32_t template_rva;          /* 0 when the module has no template */
    uint32_t template_bytes;
    uint32_t index_rva;
    uint32_t storage_bytes;         /* template_bytes + zero_fill, checked */
    uint32_t callback_count;
    PeTlsCallback callbacks[PE_TLS_MAX_CALLBACKS];
} PeTlsDirectory;

/*
 * Reads and validates the directory. An image without TLS is not an error:
 * the counts stay zero and nothing is allocated. Malformed pointers, a
 * template that is not readable, an unterminated or over-long callback array
 * and unaligned index/callback addresses all fail closed.
 */
int pe_tls_parse(PeTlsDirectory *tls, const PeImage *image);

#endif
