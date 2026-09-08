/*
 * Virtual-memory contract for manual mapping.
 *
 * A backend reserves one contiguous span per image, then commits and
 * protects sub-ranges of it. Two aliases are exposed because the PS5 has no
 * usable read-write to read-execute transition: executable memory is
 * published through a second mapping of the same pages (the jitshm double
 * mapping measured in the laboratory), so mapping writes go to write_base
 * while the image actually runs at exec_base.
 *
 * Consequence for callers: a base relocation delta is computed against
 * exec_base, the address the code will observe, and the patched bytes are
 * written through write_base. Mixing the two is the defect this split
 * exists to make impossible to write by accident.
 */
#ifndef PROSPERO_WIN_VM_H
#define PROSPERO_WIN_VM_H

#include "prospero_win.h"

/* Backend capabilities. */
enum {
    /* exec_base is a distinct mapping of the same pages as write_base. */
    PW_VM_CAP_ALIASED_EXEC = 1u << 0,
    /* protect() can change a committed range in place. */
    PW_VM_CAP_PROTECT = 1u << 1,
};

typedef struct PwVmRegion {
    void *write_base;     /* readable and writable while mapping is in progress */
    void *exec_base;      /* address the image runs from; equals write_base
                           * unless PW_VM_CAP_ALIASED_EXEC is set */
    size_t bytes;
    size_t alignment;
    void *handle;         /* backend-owned bookkeeping */
} PwVmRegion;

typedef struct PwVmBackend {
    void *context;
    unsigned capabilities;
    /*
     * Protection granularity. This is not always the PE section alignment:
     * PE images are routinely laid out on 4 KiB boundaries while a console
     * mapping is coarser, so two sections can share one protectable page
     * and the mapper has to apply the union of their protections. The count
     * of pages that needed a union is reported, never hidden.
     */
    size_t page_bytes;
    int (*reserve)(void *context, size_t bytes, size_t alignment,
                   PwVmRegion *out);
    int (*commit)(void *context, const PwVmRegion *region, size_t offset,
                  size_t bytes, unsigned protection);
    int (*protect)(void *context, const PwVmRegion *region, size_t offset,
                   size_t bytes, unsigned protection);
    int (*release)(void *context, PwVmRegion *region);
} PwVmBackend;

/* True when every required entry point is present. */
int pw_vm_backend_valid(const PwVmBackend *backend);

/* Checks that offset+bytes stays inside region without wrapping. */
int pw_vm_region_contains(const PwVmRegion *region, size_t offset,
                          size_t bytes);

#endif
