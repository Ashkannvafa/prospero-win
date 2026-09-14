/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The one piece of state a serviced Unix call needs.
 *
 * The gate used to define this structure next to everything that used it, so
 * every handler lived in one file. The adapters (files, registry, object
 * namespace, queries) and the virtual-memory service each own their logic now,
 * and this is the contract they share with the run that owns them: the guest
 * address space, the configuration and the evidence report, the module that
 * plays the process image, the guest regions this run mapped, and the typed
 * handle table.
 *
 * It is deliberately the whole of the shared state. A unit that needs
 * something else has found either a new piece of per-run state (which belongs
 * here, with its owner named) or a call that does not belong below this
 * boundary.
 */
#ifndef PROSPERO_WIN_PW_WINE_CONTEXT_H
#define PROSPERO_WIN_PW_WINE_CONTEXT_H

#include "pw_guest_vm.h"
#include "pw_nt_handle.h"
#include "pw_wine_gate.h"

typedef struct PwWineCallContext {
    PwGuestVm *vm;
    const PwWineGateConfig *config;
    PwWineGateReport *report;
    /* The module that plays the process image: ntdll's loader describes it
     * back to itself through NtQueryInformationProcess. */
    const PwModule *root;
    uint32_t heap_cursor;
    uint32_t limit;
    PwVmRegion regions[PW_WINE_GATE_MAX_CALL_REGIONS];
    /* Whether each region was allocated by an NtAllocateVirtualMemory call
     * the guest made (1) or is a page the gate registered for the guest's
     * benefit (0). Only the first kind counts against the live byte limit. */
    uint8_t region_owned[PW_WINE_GATE_MAX_CALL_REGIONS];
    uint32_t region_count;
    PwNtHandleTable handles;
} PwWineCallContext;

#endif /* PROSPERO_WIN_PW_WINE_CONTEXT_H */
