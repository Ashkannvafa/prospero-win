/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WIN64_CALL_H
#define PW_WIN64_CALL_H
#include <stdint.h>

/* Native SysV caller -> Win64 integer/pointer entry. entry must refer to
 * live executable code and args must contain six 64-bit slots. The caller
 * owns validation and lifetime. No float/aggregate/variadic support here. */
uint64_t pw_win64_call6(uintptr_t entry, const uint64_t args[6]);
#endif
