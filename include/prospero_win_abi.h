/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PROSPERO_WIN_ABI_H
#define PROSPERO_WIN_ABI_H

/* Host conformance reference: the pinned x86_64-sie-ps5 Clang target rejects
 * ms_abi. Native callers use src/pw_win64_call.h and its assembly bridge.
 * Do not suppress the target diagnostic: that would silently use SysV.
 * The guest's architecture alone does not determine the native host ABI.
 * Use this on both function definitions and function-pointer typedefs.
 * PE32 calls still require separate cdecl/stdcall marshalling. */
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#define PW_WIN64_ABI __attribute__((ms_abi))
#else
#error "The Win64 bridge requires an x86-64 compiler with ms_abi support"
#endif

#endif
