/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The guest process state a Wine ntdll finds when it starts running: a stack,
 * a TEB, a PEB and a populated RTL_USER_PROCESS_PARAMETERS.
 *
 * It is deliberately small and it is not a Windows process environment - no
 * registry, no NLS data, no drive-letter table - but every field ntdll's
 * loader and heap initialisation read is present and self-consistent, and the
 * offsets are the documented NT ones. The unit owns the four pages, so a run
 * that fails halfway releases exactly what it mapped, and the caller only has
 * to keep the layout values for its evidence.
 */
#ifndef PROSPERO_WIN_PW_GUEST_PROCESS_H
#define PROSPERO_WIN_PW_GUEST_PROCESS_H

#include "../include/prospero_win_vm.h"

enum {
    PW_GUEST_PROCESS_STACK_BASE = 0x0f000000u,
    PW_GUEST_PROCESS_TEB_BASE = 0x0e000000u,
    PW_GUEST_PROCESS_PEB_BASE = 0x0d000000u,
    PW_GUEST_PROCESS_PARAMETERS_BASE = 0x0c000000u,
    PW_GUEST_PROCESS_PAGE_BYTES = 64u * 1024u,
    PW_GUEST_PROCESS_PAGES = 4u,
    /* Where the i386 TEB keeps its embedded ACTIVATION_CONTEXT_STACK. A real
     * thread's TEB points at this field rather than at a page of its own:
     * dlls/ntdll/unix/virtual.c:4023 is the Unix side doing exactly that for
     * an i386 thread. */
    PW_GUEST_PROCESS_TEB_ACTIVATION_STACK = 0x184u,
    PW_GUEST_PROCESS_TEB_ACTIVATION_POINTER = 0x1a8u,
};

typedef struct PwGuestProcessLayout {
    uint32_t stack_base;
    uint32_t stack_bytes;
    uint32_t teb_base;
    uint32_t teb_bytes;
    uint32_t peb_base;
    uint32_t parameters_base;
    uint32_t parameters_bytes;
    uint32_t parameters_length;     /* bytes of the populated structure */
} PwGuestProcessLayout;

typedef struct PwGuestProcessConfig {
    const PwVmBackend *backend;     /* the real backend: this unit maps pages */
    uint32_t stack_base;            /* 0 selects the default above */
    uint32_t stack_bytes;           /* 0 selects the default above */
    uint32_t image_base;            /* PEB->ImageBaseAddress */
    /* Wine publishes its syscall dispatcher in TEB.WOW32Reserved, and the
     * stubs declared with -syscall=<id> call through it; 0 leaves it zero. */
    uint32_t dispatcher_thunk;
    const char *root_module;        /* canonical name, for the image paths */
    /* Which root the root module came from: 1 when the process's own image is
     * an application file and its directory is the application's, 0 when the
     * root is a system module under the Windows directory. */
    uint8_t root_application;
} PwGuestProcessConfig;

typedef struct PwGuestProcess {
    PwVmRegion pages[PW_GUEST_PROCESS_PAGES];
    /* Pages this process still owns. A release that fails keeps the page
     * here, so the caller can retry instead of losing the mapping. */
    uint32_t mapped;
    uint32_t released;              /* pages the last release gave back */
    PwGuestProcessLayout layout;
} PwGuestProcess;

/* Maps and populates the four pages. On failure nothing is left mapped. */
int pw_guest_process_create(PwGuestProcess *process,
                            const PwGuestProcessConfig *config);

/* Releases the pages this process mapped, and only those. */
int pw_guest_process_release(PwGuestProcess *process,
                             const PwVmBackend *backend);

#endif /* PROSPERO_WIN_PW_GUEST_PROCESS_H */
