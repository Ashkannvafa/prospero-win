/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Manual mapper: reserve, commit, copy, zero, relocate, protect.
 *
 * Order matters and is fixed. Everything is committed read-write, the file
 * bytes are copied, the uninitialised span is zeroed, relocations are
 * applied, and only then are the final protections installed. Import
 * binding, when it exists, happens in the read-write window too: applying
 * protections first would fault on the first thunk write.
 *
 * Verification runs before protections are installed, while every page is
 * still readable.
 */
#ifndef PROSPERO_WIN_MAP_H
#define PROSPERO_WIN_MAP_H

#include "../include/prospero_win_vm.h"
#include "pe_layout.h"
#include "pe_reloc.h"

typedef struct PwMapProtection {
    uint32_t protect_calls;
    uint32_t pages;
    uint32_t merged_pages;      /* one page, protections of several sections */
    uint32_t wx_pages;          /* writable and executable at once */
    uint32_t no_access_pages;
} PwMapProtection;

typedef struct PwMappedImage {
    PwVmRegion region;
    uint64_t preferred_base;
    uint64_t actual_base;       /* the address the image will run at */
    uint32_t image_bytes;
    uint32_t section_count;
    uint32_t entry_point;       /* RVA, copied from the layout */
    uint32_t address_bits;      /* 32 for PE32, 64 for PE32+ */
    PeRelocStats relocs;
    PwMapProtection protection;
    uint8_t protections_applied;
    uint8_t aliased_exec;
} PwMappedImage;

typedef struct PwMapVerify {
    uint32_t sections_checked;
    uint64_t bytes_compared;
    uint32_t raw_mismatches;
    uint32_t zero_tail_violations;
    uint32_t alias_mismatches;
    uint64_t checksum;          /* FNV-1a over the whole mapped image */
    uint8_t headers_present;
} PwMapVerify;

int pw_map_image(PwMappedImage *mapped, const PeImage *image,
                 const PeLayout *layout, const PwVmBackend *backend);

/*
 * Byte-level self check. Raw section bytes are compared against the file
 * only when no relocation was applied, because a rebased image is
 * deliberately no longer identical to its file; the zero-fill, alias and
 * checksum checks always run. Must be called before protections.
 */
int pw_map_verify(const PwMappedImage *mapped, const PeImage *image,
                  const PeLayout *layout, PwMapVerify *out);

int pw_map_finalize_protections(PwMappedImage *mapped, const PeLayout *layout,
                                const PwVmBackend *backend);

int pw_map_release(PwMappedImage *mapped, const PwVmBackend *backend);

/* Writable alias of rva..rva+bytes, or NULL. */
void *pw_map_writable(const PwMappedImage *mapped, uint32_t rva, size_t bytes);

/* Address the running image observes for rva, or 0. */
uint64_t pw_map_exec_address(const PwMappedImage *mapped, uint32_t rva);

#endif
