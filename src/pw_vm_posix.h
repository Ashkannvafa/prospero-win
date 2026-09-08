/*
 * POSIX memory backend: anonymous mappings, protection through mprotect and
 * a single alias for writes and execution.
 *
 * It is the host-test backend and also the plain path on the console for
 * images that are only mapped and inspected. Executing mapped code on the
 * PS5 needs the aliased backend instead, because a read-write to
 * read-execute transition is not a supported operation there.
 */
#ifndef PROSPERO_WIN_VM_POSIX_H
#define PROSPERO_WIN_VM_POSIX_H

#include "../include/prospero_win_vm.h"

int pw_vm_posix_backend(PwVmBackend *backend);

#endif
