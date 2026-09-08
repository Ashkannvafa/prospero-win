/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WIN32_H
#define PW_WIN32_H
#include "pw_import_bind.h"
#include "pw_guest_call.h"
enum { PW_WIN32_TOKEN_BASE=0xe0000000u };
typedef struct PwWin32 {
    uint32_t main_base,crt_data,app_type;
    const char *last_dll,*last_name;
    unsigned calls;
} PwWin32;
/* Caller supplies a live RW, identity-mapped CRT region of at least 4096
 * bytes. Tokens occupy [TOKEN_BASE,TOKEN_BASE+catalog_count*16); the owner
 * must keep that range separate from guest image/data/stack mappings. */
int pw_win32_init(PwWin32 *runtime,uint32_t main_base,uint32_t crt_data,
                  const char *guest_command_line);
int pw_win32_resolve(void *,const char *,const PeImportSymbol *,PwImportTarget *);
/* PW_ERR_NOT_FOUND: not a token; UNSUPPORTED: named API/argument not covered.
 * No pending API reports success. Dispatcher must intercept tokens before
 * code fetch. Initial surface: GetModuleHandleA(NULL), __set_app_type,
 * __p__fmode, __p__commode and _controlfp (requires initialized state.fp).
 * CRT pointer results refer to live guest words. */
int pw_win32_dispatch(PwWin32 *,PwX86State *);
#endif
