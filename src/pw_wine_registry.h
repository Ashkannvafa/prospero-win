/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The registry adapter: NtOpenKey, NtCreateKey and NtQueryValueKey.
 *
 * Wine's registry is host state, so the profile behind PwWineRegistryService
 * decides what exists. This unit owns the translation and the guarantees: one
 * canonical key path per guest name (absolute under the two NT roots, or
 * relative to a key handle this run owns), validated components, KEY_VALUE_*
 * answers laid out the way NT lays them out, and STATUS_OBJECT_NAME_NOT_FOUND
 * for anything the profile does not declare - which is what makes ntdll fall
 * back to its own defaults instead of seeing invented content.
 */
#ifndef PROSPERO_WIN_PW_WINE_REGISTRY_H
#define PROSPERO_WIN_PW_WINE_REGISTRY_H

#include "pw_nt_dispatch.h"

struct PwWineCallContext;

/* NtOpenKey (0x0012). */
int pw_wine_registry_open(struct PwWineCallContext *calls,
                          const PwUnixCallFrame *frame, PwUnixCallAccess guest,
                          void *context, uint32_t *status,
                          uint32_t *argument_index);

/* NtCreateKey (0x001d): create-or-open, as NT defines it. */
int pw_wine_registry_create(struct PwWineCallContext *calls,
                            const PwUnixCallFrame *frame,
                            PwUnixCallAccess guest, void *context,
                            uint32_t *status, uint32_t *argument_index);

/* NtQueryValueKey (0x0017), KeyValuePartialInformation only. */
int pw_wine_registry_query_value(struct PwWineCallContext *calls,
                                 const PwUnixCallFrame *frame,
                                 PwUnixCallAccess guest, void *context,
                                 uint32_t *status, uint32_t *argument_index);

#endif /* PROSPERO_WIN_PW_WINE_REGISTRY_H */
