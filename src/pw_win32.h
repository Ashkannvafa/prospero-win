/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WIN32_H
#define PW_WIN32_H
#include "pw_import_bind.h"
#include "pw_guest_call.h"
#include "pw_guest_args.h"
#include "pw_guest_heap.h"
#include "pw_registry.h"
enum { PW_WIN32_TOKEN_BASE=0xe0000000u, PW_WIN32_CALLBACK_BASE=0xe1000000u,
       PW_WIN32_INIT_DEPTH=8, PW_WIN32_INIT_ENTRIES=1024 };
typedef struct PwWin32Init {
    PwGuestCall call;
    PwGuestCallback callback;
    uint32_t cursor,end;
} PwWin32Init;
typedef enum PwClockDomain { PW_CLOCK_UTC=1, PW_CLOCK_UPTIME=2, PW_CLOCK_COUNTER=3 } PwClockDomain;
typedef struct PwWin32Services {
    void *opaque;
    /* UTC: nanoseconds since Unix epoch (nonnegative); uptime: ns since boot
     * including suspend; counter: monotonic nanoseconds, frequency 1 GHz.
     * Return PW_OK only when the selected domain was actually sampled. */
    int (*clock_ns)(void *,PwClockDomain,uint64_t *);
    uint32_t process_id,thread_id; /* guest registry IDs, not host handles */
    /* Borrowed UTF-16LE from a live module's resources. NOT_FOUND is absence,
     * not malformed input. Provider owns module and language selection. */
    int (*string_resource)(void *,uint32_t,uint32_t,const uint8_t **,size_t *);
    unsigned ansi_codepage; /* currently exact CP1252 conversion only */
} PwWin32Services;
typedef struct PwWin32 {
    uint32_t main_base,crt_data,app_type;
    PwGuestArgs args;
    uint32_t new_mode;
    PwGuestHeap *heap; /* owner-supplied arena, registered RW in guest memory */
    PwRegistry *registry; /* owner-supplied fixed-capacity Win32 registry */
    uint32_t crt_errno; /* logical per-guest-thread errno; pointer export pending */
    uint32_t last_error; /* Win32 per-guest-thread error, distinct from CRT errno */
    uint16_t startup_show; /* explicit GUI launch profile: SW_SHOWNORMAL by default */
    PwWin32Services services;
    const char *last_dll,*last_name;
    unsigned calls;
    unsigned callback_pending,init_depth;
    PwWin32Init init[PW_WIN32_INIT_DEPTH];
} PwWin32;
/* Caller supplies a live RW, identity-mapped CRT region of at least 4096
 * bytes. Tokens occupy [TOKEN_BASE,TOKEN_BASE+catalog_count*16); the owner
 * must keep that range and [CALLBACK_BASE,CALLBACK_BASE+INIT_DEPTH*16)
 * separate from guest image/data/stack mappings. Runtime is guest-thread-owned.
 * Initialization packs command line, argv and an explicitly empty environment
 * into this region; combined storage must fit. Failure leaves it unchanged. */
int pw_win32_init(PwWin32 *runtime,uint32_t main_base,uint32_t crt_data,
                  const char *guest_command_line);
int pw_win32_resolve(void *,const char *,const PeImportSymbol *,PwImportTarget *);
/* PW_ERR_NOT_FOUND: not a token; UNSUPPORTED: named API/argument not covered.
 * No pending API reports success. Dispatcher must intercept tokens before
 * code fetch. Initial surface: GetModuleHandleA(NULL), __set_app_type,
 * __p__fmode, __p__commode and _controlfp (requires initialized state.fp).
 * __getmainargs supports non-wildcard argv/env and new_mode 0/1. The imported
 * Advapi registry group dispatches through owner-supplied PwRegistry storage.
 * _initterm can schedule guest callbacks: PW_OK with callback_pending=1 is
 * a yield, not an API return; fetch guest EIP next. Intercept callback tokens
 * here before fetching code. CRT pointer results refer to live guest words. */
int pw_win32_dispatch(PwWin32 *,PwX86State *);
#endif
