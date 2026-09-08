/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_EXEC_PROBE_H
#define PW_EXEC_PROBE_H
#include "../include/prospero_win_vm.h"
typedef struct PwExecProbe {
    uint64_t constant, alignment, weighted, high;
    unsigned sealed, released;
} PwExecProbe;
/* Executes project-authored Win64 instructions only, never the staged PE. */
int pw_exec_probe(const PwVmBackend *backend, PwExecProbe *report);
#endif
