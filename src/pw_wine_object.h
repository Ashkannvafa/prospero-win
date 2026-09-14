/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The object-namespace adapter: NtOpenDirectoryObject and NtOpenSection.
 *
 * A Wine loader asks for \KnownDlls and for sections inside it, so the profile
 * behind PwWineObjectService says what the namespace contains; a name it does
 * not declare answers STATUS_OBJECT_NAME_NOT_FOUND, which is what makes the
 * loader fall back to the file system exactly as Wine does on a prefix without
 * known DLLs. This unit owns the path translation (absolute, or relative to a
 * directory handle this run owns), the object kind it hands the service, and
 * the typed handle the guest gets back.
 */
#ifndef PROSPERO_WIN_PW_WINE_OBJECT_H
#define PROSPERO_WIN_PW_WINE_OBJECT_H

#include "pw_nt_dispatch.h"

struct PwWineCallContext;

/* NtOpenDirectoryObject (0x0058). */
int pw_wine_object_open_directory(struct PwWineCallContext *calls,
                                  const PwUnixCallFrame *frame,
                                  PwUnixCallAccess guest, void *context,
                                  uint32_t *status, uint32_t *argument_index);

/* NtOpenSection (0x0037). */
int pw_wine_object_open_section(struct PwWineCallContext *calls,
                                const PwUnixCallFrame *frame,
                                PwUnixCallAccess guest, void *context,
                                uint32_t *status, uint32_t *argument_index);

#endif /* PROSPERO_WIN_PW_WINE_OBJECT_H */
