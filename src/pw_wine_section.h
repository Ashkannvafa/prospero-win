/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Image sections: NtCreateSection over an open file handle, and
 * NtQuerySection for the two classes that describe one.
 *
 * ntdll's own loader opens a DLL file, creates a SEC_IMAGE section over it and
 * asks that section for its SECTION_IMAGE_INFORMATION before it decides the
 * image is one this process can run (dlls/ntdll/loader.c:2696-2745,
 * is_valid_binary). The section, not the file, is then the thing a view is
 * mapped from, so a section outlives the file handle it was created from: the
 * loader closes that handle as soon as the section exists.
 *
 * This unit answers both calls out of the file's own bytes and keeps the
 * section's description - including the canonical name it can re-open the file
 * by - in the run's context, because the view mapping that follows needs it
 * again after the handle is gone.
 *
 * SECTION_IMAGE_INFORMATION's layout and the ImageFlags bits live here as well
 * because two units produce that structure: this one for a section and
 * pw_wine_query.c for the image the process is running. One definition, so the
 * two answers cannot drift apart.
 */
#ifndef PROSPERO_WIN_PW_WINE_SECTION_H
#define PROSPERO_WIN_PW_WINE_SECTION_H

#include "pw_nt_dispatch.h"

struct PwWineCallContext;

enum {
    /* SECTION_INFORMATION_CLASS values. */
    PW_WINE_SECTION_BASIC_INFORMATION = 0u,
    PW_WINE_SECTION_IMAGE_INFORMATION = 1u,
    /* SECTION_IMAGE_INFORMATION, as an i386 guest lays it out. */
    PW_WINE_SECTION_IMAGE_BYTES = 48u,
    PW_WINE_SECTION_BASIC_BYTES = 12u,
    /* ImageFlags: the image was relocated when it was mapped, and it lives
     * below 4 GiB. Nothing else applies to a native i386 PE. */
    PW_WINE_IMAGE_FLAG_DYNAMICALLY_RELOCATED = 0x04u,
    PW_WINE_IMAGE_FLAG_BASE_BELOW_4GB = 0x10u,
    /* How much of a file is read to describe the image it holds: the DOS and
     * NT headers and the section table, which is everything a description and
     * a view mapping need from the file itself. */
    PW_WINE_SECTION_HEADER_BYTES = 4096u,
    PW_WINE_SECTION_PAGE_BYTES = 0x1000u,
    /* The one view shape a loader asks for, and the one protection it asks
     * for: NtMapViewOfSection(mapping, NtCurrentProcess(), &module, 0, 0,
     * NULL, &len, ViewShare, 0, PAGE_EXECUTE_READ). */
    PW_WINE_SECTION_VIEW_SHARE = 1u,
    PW_WINE_SECTION_VIEW_UNMAP = 2u,
    PW_WINE_SECTION_PAGE_EXECUTE_READ = 0x20u,
    PW_WINE_SECTION_PAGE_READWRITE = 0x04u,
};

/* NtCreateSection (0x004a), SEC_IMAGE over an open file handle. */
int pw_wine_section_create(struct PwWineCallContext *calls,
                           const PwUnixCallFrame *frame, PwUnixCallAccess guest,
                           void *context, uint32_t *status,
                           uint32_t *argument_index);

/* NtQuerySection (0x0051): SectionBasicInformation and
 * SectionImageInformation, which are the two classes a section can answer. */
int pw_wine_section_query(struct PwWineCallContext *calls,
                          const PwUnixCallFrame *frame, PwUnixCallAccess guest,
                          void *context, uint32_t *status,
                          uint32_t *argument_index);

/* NtMapViewOfSection (0x0028): the view a loader maps an image section into,
 * placed per the image's own section table and described to the guest. */
int pw_wine_section_map_view(struct PwWineCallContext *calls,
                             const PwUnixCallFrame *frame,
                             PwUnixCallAccess guest, void *context,
                             uint32_t *status, uint32_t *argument_index);

#endif /* PROSPERO_WIN_PW_WINE_SECTION_H */
