/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The second Wine boundary: the PE-side Unix-call dispatcher.
 *
 * Wine's PE modules reach the Unix side through two different doors. The
 * syscall stubs (loaded into EAX, jumped through __wine_syscall_dispatcher)
 * are the first, and src/pw_unix_call.[ch] carries their versioned table. The
 * second is a pair of *data exports*:
 *
 *   extern unixlib_handle_t __wine_unixlib_handle;
 *   extern NTSTATUS (WINAPI *__wine_unix_call_dispatcher)( unixlib_handle_t,
 *                                                          unsigned int, void * );
 *   WINE_UNIX_CALL(code,args) ==
 *       __wine_unix_call_dispatcher( __wine_unixlib_handle, code, args )
 *
 * (include/wine/unixlib.h:281-301 at the pinned revision.) In Wine the handle
 * value is the host address of the unix_call_funcs[] table and the dispatcher
 * is the assembly entry in dlls/ntdll/unix/signal_i386.c. Here the handle is an
 * opaque identifier bound to the pinned runtime - never a host pointer and
 * never a guest pointer to a host array - and the dispatcher is a project-owned
 * guest boundary address, so a guest can never make the host execute a pointer
 * it supplied.
 *
 * The code space is the `enum ntdll_unix_funcs` order from
 * dlls/ntdll/unixlib.h, which is the same order as the unix_call_funcs[] table
 * in dlls/ntdll/unix/loader.c:1009-1019. `tests/test_unixlib_table.py`
 * re-derives both from the pinned source, so the table below cannot drift
 * silently, and it always runs its structural checks even when no Wine
 * checkout is present.
 */
#ifndef PROSPERO_WIN_PW_UNIXLIB_H
#define PROSPERO_WIN_PW_UNIXLIB_H

#include "../include/prospero_win.h"

/* The Wine revision the codes and layouts below are taken from. */
#define PW_UNIXLIB_WINE_COMMIT "490f6d5dcbb2a5047345b8af88d114bbcaad69a8"

enum {
    /* enum ntdll_unix_funcs: eight entries at the pinned revision. */
    PW_UNIXLIB_MAX_FUNCS = 8,
    PW_UNIXLIB_NAME_MAX = 31,
};

/* The first observed call of the pinned trace: __wine_dbg_write ->
 * WINE_UNIX_CALL(unix_wine_dbg_write, &params) in dlls/ntdll/thread.c. */
enum {
    PW_UNIXLIB_CODE_LOAD_SO_DLL = 0,
    PW_UNIXLIB_CODE_UNWIND_BUILTIN_DLL = 1,
    PW_UNIXLIB_CODE_WINE_DBG_WRITE = 2,
    PW_UNIXLIB_CODE_WINE_SERVER_CALL = 3,
    PW_UNIXLIB_CODE_SERVER_FD_TO_HANDLE = 4,
    PW_UNIXLIB_CODE_SERVER_HANDLE_TO_FD = 5,
    PW_UNIXLIB_CODE_WINE_SPAWNVP = 6,
    PW_UNIXLIB_CODE_SYSTEM_TIME_PRECISE = 7,
};

/*
 * `struct wine_dbg_write_params { const char *str; unsigned int len; }`
 * (dlls/ntdll/unixlib.h). On i386 the pointer is 4 bytes and `len` follows it
 * at offset 4; the struct is 8 bytes, and `str` is a *guest* pointer that only
 * the dispatcher's validated accessor may dereference.
 */
enum {
    PW_UNIXLIB_DBG_WRITE_PARAMS_BYTES = 8,
    PW_UNIXLIB_DBG_WRITE_STR_OFFSET = 0,
    PW_UNIXLIB_DBG_WRITE_LEN_OFFSET = 4,
};

typedef struct PwUnixlibFunc {
    uint32_t code;
    const char *name;               /* the enum ntdll_unix_funcs name */
} PwUnixlibFunc;

/* Every entry of the pinned code space, in order. */
const PwUnixlibFunc *pw_unixlib_funcs(uint32_t *count);

/* The entry for a code, or NULL when the code is outside the pinned table. */
const PwUnixlibFunc *pw_unixlib_lookup(uint32_t code);

#endif /* PROSPERO_WIN_PW_UNIXLIB_H */
