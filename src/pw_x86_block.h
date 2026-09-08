/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_X86_BLOCK_H
#define PW_X86_BLOCK_H
#include <stddef.h>
#include <stdint.h>
#include "pw_guest_fp.h"
#include "../include/prospero_win.h"

enum { PW_X86_MEMORY_REGIONS=8, PW_X86_READ=1, PW_X86_WRITE=2 };
typedef struct PwX86Memory {
    uint32_t low;
    uint64_t high; /* exclusive; can represent 4 GiB */
    unsigned permissions;
} PwX86Memory;
typedef struct PwX86State {
    uint32_t gpr[8]; /* eax ecx edx ebx esp ebp esi edi */
    uint32_t eip;
    uint32_t stack_low, stack_high; /* mapped RW range, high exclusive */
    uint32_t fs_base, fs_bytes; /* guest-owned RW thread region, not host FS */
    uint32_t eflags; /* guest flags; never installed as host control flags */
    unsigned memory_count;
    PwX86Memory memory[PW_X86_MEMORY_REGIONS]; /* live identity-mapped ranges */
    PwGuestFp fp;
} PwX86State;

typedef struct PwX86Block {
    size_t source_bytes, code_bytes;
    uint32_t instructions;
} PwX86Block;

/* Initial bounded DBT subset: push immediate/register/memory, pop register,
 * mov register/immediate, register/register or registered memory (ModRM/SIB),
 * MOV immediate/register or memory, register ADD/SUB/XOR with arithmetic flags,
 * immediate ALU 16/32-bit (ADD/OR/ADC/SBB/AND/SUB/XOR/CMP),
 * CMP register/memory 32-bit, TEST 32-bit register/memory/immediate, MOVZX word,
 * short/near Jcc and register-byte SETcc using guest arithmetic flags,
 * LEA, absolute and FS moffs32/EAX loads/stores, nop,
 * direct/indirect near call/jump and ret. No copied 32-bit stack instructions. A successful
 * block is a SysV int(PwX86State*) function returning 0, or -1 on memory bounds.
 * Direct transfers update guest EIP and return to the dispatcher.
 * Stack range must be live RW identity-mapped guest memory below 4 GiB.
 * FS range must also be live RW guest memory; no host segment state is used.
 * Additional memory ranges must be live identity mappings with the declared
 * permissions. Generated code embeds a process-local memory-check helper.
 * Output is unexecutable scratch on failure; never publish failed output.
 * This is not an x86 engine yet: unsupported instructions stop translation. */
int pw_x86_translate(const uint8_t *source, size_t bytes, uint32_t guest_pc,
                     uint8_t *output, size_t capacity, PwX86Block *block);
#endif
