/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The address space a Wine guest gets: the runtime modules and every block
 * ntdll asks the platform for.
 *
 * Two things belong here rather than in the gate. The first is the
 * low-address policy: the portable mapper refuses a PE32 image the guest could
 * not address, so a relocatable Wine DLL has to be reserved below 4 GiB
 * instead of wherever the host would put it. The second is the contract with
 * the backend underneath: this unit keeps the caller's vtable *and its context
 * exactly as it received them*, and never borrows the context field for its
 * own state. A backend is entitled to use that field; the gate used to
 * overwrite it, which is invisible with today's stateless posix backend and
 * immediately fatal with one that keeps state there.
 */
#ifndef PROSPERO_WIN_PW_GUEST_VM_H
#define PROSPERO_WIN_PW_GUEST_VM_H

#include "../include/prospero_win_vm.h"

enum {
    /* The window the runtime modules and the guest's own pages are laid out
     * in: below the 32-bit boundary a PE32 image needs. */
    PW_GUEST_VM_LOW_BASE = 0x10000000u,
    PW_GUEST_VM_LOW_LIMIT = 0x40000000u,
    PW_GUEST_VM_MAX_IMAGE_BYTES = 32u * 1024u * 1024u,
    /*
     * How many exact-address candidates one low reservation may try before it
     * gives up and reports exhaustion. The whole window is 196 608 candidates
     * at 4 KiB, and walking all of them for every mapping attempt is work no
     * guest asked for; the caller still falls back to a plain reservation, and
     * exhaustion is reported so the reason a PE32 mapping failed is visible.
     */
    PW_GUEST_VM_MAX_CANDIDATES = 4096,
};

typedef struct PwGuestVm {
    /* The caller's backend, untouched: vtable and context both. */
    PwVmBackend base;
    /* The vtable this unit hands out. Its context is the owner below. */
    PwVmBackend low;
    uint32_t cursor;
    uint32_t exhausted;     /* the last low reservation found no candidate */
} PwGuestVm;

void pw_guest_vm_init(PwGuestVm *vm, const PwVmBackend *base);

/* The vtable to give the loader and the call handlers. */
const PwVmBackend *pw_guest_vm_backend(PwGuestVm *vm);

/* True when the last low reservation used up its candidate budget and fell
 * back: a PE32 image that lands on the fallback will be refused above it. */
int pw_guest_vm_exhausted(const PwGuestVm *vm);

void pw_guest_vm_reset(PwGuestVm *vm);

#endif /* PROSPERO_WIN_PW_GUEST_VM_H */
