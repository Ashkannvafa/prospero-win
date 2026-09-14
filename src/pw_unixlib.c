/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_unixlib.h"

/*
 * enum ntdll_unix_funcs, in the order dlls/ntdll/unix/loader.c uses for
 * unix_call_funcs[] at the pinned revision. Both files are re-parsed by
 * tests/test_unixlib_table.py, so an added, removed or reordered entry fails
 * the suite instead of shifting the meaning of a code the guest passes.
 */
static const PwUnixlibFunc table[PW_UNIXLIB_MAX_FUNCS] = {
    { PW_UNIXLIB_CODE_LOAD_SO_DLL, "unix_load_so_dll" },
    { PW_UNIXLIB_CODE_UNWIND_BUILTIN_DLL, "unix_unwind_builtin_dll" },
    { PW_UNIXLIB_CODE_WINE_DBG_WRITE, "unix_wine_dbg_write" },
    { PW_UNIXLIB_CODE_WINE_SERVER_CALL, "unix_wine_server_call" },
    { PW_UNIXLIB_CODE_SERVER_FD_TO_HANDLE, "unix_wine_server_fd_to_handle" },
    { PW_UNIXLIB_CODE_SERVER_HANDLE_TO_FD, "unix_wine_server_handle_to_fd" },
    { PW_UNIXLIB_CODE_WINE_SPAWNVP, "unix_wine_spawnvp" },
    { PW_UNIXLIB_CODE_SYSTEM_TIME_PRECISE, "unix_system_time_precise" },
};

const PwUnixlibFunc *pw_unixlib_funcs(uint32_t *count)
{
    if (count)
        *count = (uint32_t)PW_UNIXLIB_MAX_FUNCS;
    return table;
}

const PwUnixlibFunc *pw_unixlib_lookup(uint32_t code)
{
    if (code >= (uint32_t)PW_UNIXLIB_MAX_FUNCS)
        return NULL;
    return &table[code];
}
