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
#include "pw_loader.h"
#include "pw_nt_handle.h"
#include "pw_wine_gate.h"

/*
 * One image section: what NtQuerySection answers from, and the canonical name
 * the view mapping re-opens the file by once the file handle is closed.
 */
typedef struct PwWineSection {
    char name[PW_NT_HANDLE_PATH_MAX + 1];
    uint64_t file_size;
    uint64_t image_base;
    uint32_t protection;
    uint32_t attributes;
    uint32_t image_size;
    uint32_t entry_point;
    uint32_t stack_reserve;
    uint32_t stack_commit;
    uint32_t checksum;
    uint32_t subsystem;
    uint16_t subsystem_version_minor;
    uint16_t subsystem_version_major;
    uint16_t os_version_major;
    uint16_t os_version_minor;
    uint16_t characteristics;
    uint16_t dll_characteristics;
    uint16_t machine;
    uint8_t contains_code;
    uint8_t image_flags;
} PwWineSection;

typedef struct PwWineCallContext {
    PwGuestVm *vm;
    const PwWineGateConfig *config;
    PwWineGateReport *report;
    /* The module that plays the process image: ntdll's loader describes it
     * back to itself through NtQueryInformationProcess. */
    const PwModule *root;
    /* The whole module graph, because a question about an address is a
     * question about every module this run mapped, not only the root:
     * ntdll's loader asks where the ntdll image it was started inside lives
     * (build_ntdll_module, dlls/ntdll/loader.c:2362) before it has a module
     * record for it, so the answer cannot come from the inventory it is
     * about to build. */
    const PwLoader *loader;
    uint32_t heap_cursor;
    uint32_t limit;
    PwVmRegion regions[PW_WINE_GATE_MAX_CALL_REGIONS];
    /* Whether each region was allocated by an NtAllocateVirtualMemory call
     * the guest made (1) or is a page the gate registered for the guest's
     * benefit (0). Only the first kind counts against the live byte limit. */
    uint8_t region_owned[PW_WINE_GATE_MAX_CALL_REGIONS];
    uint32_t region_count;
    PwNtHandleTable handles;
    /*
     * The image sections this run created. A section outlives the file handle
     * it was created from - ntdll's loader closes that handle as soon as the
     * section exists and maps a view from the section afterwards - so the
     * section keeps its own description plus the canonical name it can re-open
     * the file by, and the handle names an entry here rather than the file.
     */
    PwWineSection sections[PW_WINE_GATE_MAX_SECTIONS];
    uint32_t section_count;
} PwWineCallContext;

#endif /* PROSPERO_WIN_PW_WINE_CONTEXT_H */
