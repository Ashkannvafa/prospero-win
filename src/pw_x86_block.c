/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_x86_block.h"
#include <string.h>

typedef struct Emitter { uint8_t *p; size_t n, cap; int failed; } Emitter;
static void byte(Emitter *e, uint8_t value)
{
    if (e->n == e->cap) { e->failed = 1; return; }
    e->p[e->n++] = value;
}
static void word(Emitter *e, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) byte(e, (uint8_t)(value >> (8*i)));
}
static uint32_t read32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static void store(Emitter *e, size_t offset, uint32_t value)
{
    byte(e,0xc7); byte(e,0x47); byte(e,(uint8_t)offset); word(e,value);
}
static void load_eax(Emitter *e, size_t offset)
{
    byte(e,0x8b); byte(e,0x47); byte(e,(uint8_t)offset);
}
static void store_eax(Emitter *e, size_t offset)
{
    byte(e,0x89); byte(e,0x47); byte(e,(uint8_t)offset);
}
/* A failed comparison returns -1. The short branch skips mov eax,-1; ret. */
static void require_condition(Emitter *e, uint8_t condition)
{
    byte(e,condition); byte(e,6); byte(e,0xb8); word(e,0xffffffffu); byte(e,0xc3);
}
static void stack_address(Emitter *e, int push)
{
    load_eax(e,offsetof(PwX86State,gpr[4]));
    if (push) {
        /* Check before subtracting: an ESP of 0 must not wrap. */
        byte(e,0x83); byte(e,0xf8); byte(e,4);
        require_condition(e,0x73); /* jae */
        byte(e,0x83); byte(e,0xe8); byte(e,4);
    }
    byte(e,0x3b); byte(e,0x47); byte(e,offsetof(PwX86State,stack_low));
    require_condition(e,0x73);
    /* edx = high; require high >= 4; then address <= high-4 */
    byte(e,0x8b); byte(e,0x57); byte(e,offsetof(PwX86State,stack_high));
    byte(e,0x83); byte(e,0xfa); byte(e,4); require_condition(e,0x73);
    byte(e,0x83); byte(e,0xea); byte(e,4);
    byte(e,0x39); byte(e,0xd0); require_condition(e,0x76); /* jbe */
}
static void push_imm(Emitter *e, uint32_t value)
{
    stack_address(e,1);
    byte(e,0xc7); byte(e,0x00); word(e,value); /* mov dword [rax],imm32 */
    store_eax(e,offsetof(PwX86State,gpr[4]));
}
static void success(Emitter *e)
{
    byte(e,0x31); byte(e,0xc0); byte(e,0xc3);
}

int pw_x86_translate(const uint8_t *source, size_t bytes, uint32_t pc,
                     uint8_t *output, size_t capacity, PwX86Block *block)
{
    Emitter e = {output,0,capacity,0};
    size_t cursor = 0;
    unsigned count = 0;
    if (!source || !bytes || !output || !capacity || !block)
        return PW_ERR_PRECONDITION;
    memset(block,0,sizeof(*block));
    while (cursor < bytes && count < 32) {
        const uint8_t op = source[cursor];
        size_t length;
        int terminal = 0;
        if (op == 0x6a || op == 0xeb) length = 2;
        else if (op == 0x68 || op == 0xe8 || op == 0xe9 ||
                 (op >= 0xb8 && op <= 0xbf)) length = 5;
        else if (op == 0xc3 || op == 0x90 || (op >= 0x50 && op <= 0x5f)) length = 1;
        else return PW_ERR_UNSUPPORTED;
        if (length > bytes-cursor) return PW_ERR_TRUNCATED;
        uint32_t next = pc + (uint32_t)cursor + (uint32_t)length;
        /* Fault exits preserve the PC of the faulting guest instruction. */
        store(&e,offsetof(PwX86State,eip),pc+(uint32_t)cursor);
        if (op == 0x6a) push_imm(&e,(uint32_t)(int32_t)(int8_t)source[cursor+1]);
        else if (op == 0x68) push_imm(&e,read32(source+cursor+1));
        else if (op >= 0x50 && op <= 0x57) {
            stack_address(&e,1);
            /* Read the old register value before committing ESP (push esp). */
            byte(&e,0x8b); byte(&e,0x4f); byte(&e,(op-0x50)*4);
            byte(&e,0x89); byte(&e,0x08);
            store_eax(&e,offsetof(PwX86State,gpr[4]));
        } else if (op >= 0x58 && op <= 0x5f) {
            stack_address(&e,0);
            byte(&e,0x8b); byte(&e,0x08);
            byte(&e,0x83); byte(&e,0xc0); byte(&e,4);
            store_eax(&e,offsetof(PwX86State,gpr[4]));
            /* Pop esp replaces the incremented ESP with the popped value. */
            byte(&e,0x89); byte(&e,0x4f); byte(&e,(op-0x58)*4);
        }
        else if (op >= 0xb8 && op <= 0xbf)
            store(&e,offsetof(PwX86State,gpr)+(op-0xb8)*4,read32(source+cursor+1));
        else if (op == 0xe8 || op == 0xe9 || op == 0xeb) {
            if (op == 0xe8) push_imm(&e,next);
            uint32_t delta = op == 0xeb ? (uint32_t)(int32_t)(int8_t)source[cursor+1]
                                      : read32(source+cursor+1);
            next += delta;
            terminal = 1;
        } else if (op == 0xc3) {
            stack_address(&e,0);
            byte(&e,0x8b); byte(&e,0x08); /* ecx = guest return */
            byte(&e,0x83); byte(&e,0xc0); byte(&e,4);
            store_eax(&e,offsetof(PwX86State,gpr[4]));
            byte(&e,0x89); byte(&e,0x4f); byte(&e,offsetof(PwX86State,eip));
            terminal = 1;
        }
        if (op != 0xc3) store(&e,offsetof(PwX86State,eip),next);
        cursor += length; ++count;
        if (terminal) break;
    }
    success(&e);
    if (e.failed) return PW_ERR_LIMIT;
    block->source_bytes = cursor; block->code_bytes = e.n; block->instructions = count;
    return PW_OK;
}
