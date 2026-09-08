/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_X86_BLOCK_H
#define PW_X86_BLOCK_H
#include <stddef.h>
#include <stdint.h>
#include "../include/prospero_win.h"

typedef struct PwX86State {
    uint32_t gpr[8]; /* eax ecx edx ebx esp ebp esi edi */
    uint32_t eip;
    uint32_t stack_low, stack_high; /* mapped RW range, high exclusive */
    uint32_t fs_base, fs_bytes; /* guest-owned RW thread region, not host FS */
    uint32_t eflags; /* guest flags; never installed as host control flags */
} PwX86State;

typedef struct PwX86Block {
    size_t source_bytes, code_bytes;
    uint32_t instructions;
} PwX86Block;

/* Initial bounded DBT subset: push immediate/register, pop register,
 * mov register/immediate, register/register or stack memory (ModRM/SIB),
 * MOV immediate/register or stack-memory, register SUB with arithmetic flags,
 * LEA, FS moffs32/EAX, nop,
 * direct call/jump and ret. No copied 32-bit stack instructions. A successful
 * block is a SysV int(PwX86State*) function returning 0, or -1 on memory bounds.
 * Direct transfers update guest EIP and return to the dispatcher.
 * Stack range must be live RW identity-mapped guest memory below 4 GiB.
 * FS range must also be live RW guest memory; no host segment state is used.
 * Output is unexecutable scratch on failure; never publish failed output.
 * This is not an x86 engine yet: unsupported instructions stop translation. */
int pw_x86_translate(const uint8_t *source, size_t bytes, uint32_t guest_pc,
                     uint8_t *output, size_t capacity, PwX86Block *block);
#endif
