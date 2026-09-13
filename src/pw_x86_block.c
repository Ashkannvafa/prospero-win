/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_x86_block.h"
#include "pw_x87.h"
#include <string.h>

/* Context accesses below use signed disp8 encodings. Fail at build time if
 * future state-layout changes would silently address the wrong field. */
_Static_assert(offsetof(PwX86State,eflags)<=127,"context exceeds disp8 layout");
_Static_assert(offsetof(PwX86State,memory[0].permissions)<=127,
               "generated memory fast path exceeds disp8 layout");

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
static void stack_bounds(Emitter *e)
{
    byte(e,0x3b); byte(e,0x47); byte(e,offsetof(PwX86State,stack_low));
    require_condition(e,0x73);
    byte(e,0x8b); byte(e,0x57); byte(e,offsetof(PwX86State,stack_high));
    byte(e,0x83); byte(e,0xfa); byte(e,4); require_condition(e,0x73);
    byte(e,0x83); byte(e,0xea); byte(e,4);
    byte(e,0x39); byte(e,0xd0); require_condition(e,0x76);
}
static uintptr_t memory_range_pointer(PwX86State *state,uint32_t address,unsigned write,uint64_t width)
{
    uint64_t end=(uint64_t)address+width;
    unsigned permission=write==2?(PW_X86_READ|PW_X86_WRITE):write?PW_X86_WRITE:PW_X86_READ;
    if (!address || !width || end>0x100000000ull || state->memory_count>PW_X86_MEMORY_REGIONS)
        return 0;
    if(address>=state->stack_low && end<=state->stack_high)return address;
    for(unsigned i=0;i<state->memory_count;i++) {
        const PwX86Memory *m=&state->memory[i];
        if(m->high<=0x100000000ull && address>=m->low && end<=m->high &&
           (m->permissions&permission)==permission)return address;
    }
    return 0;
}
static uintptr_t memory_pointer(PwX86State *state,uint32_t address,unsigned write,unsigned width)
{
    if(width!=1 && width!=2 && width!=4 && width!=8 && width!=10)return 0;
    return memory_range_pointer(state,address,write,width);
}
static void memory_address_width(Emitter *e,unsigned write,unsigned width)
{
    /* Preserve the slow helper's state-contract checks before taking either
     * inline path.  In particular, a corrupt registry must not make even the
     * otherwise-valid stack path executable, and guest NULL is never a valid
     * identity-mapped pointer. */
    byte(e, 0x83); byte(e, 0x7f); byte(e, offsetof(PwX86State, memory_count));
    byte(e, PW_X86_MEMORY_REGIONS); /* cmp dword [rdi + memory_count], max */
    byte(e, 0x77); /* ja to slow_path */
    size_t patch_ja_count = e->n++;
    byte(e, 0x85); byte(e, 0xc0); /* test eax, eax */
    byte(e, 0x74); /* jz to slow_path */
    size_t patch_jz_null = e->n++;

    /* 1. Fast path: check stack [stack_low, stack_high).
     * If stack_low <= EAX && EAX + width <= stack_high, address is valid RW stack. */
    byte(e, 0x3b); byte(e, 0x47); byte(e, offsetof(PwX86State, stack_low)); /* cmp eax, [rdi + stack_low] */
    byte(e, 0x72); /* jb to try_mem0 */
    size_t patch_jb_stack = e->n++;

    byte(e, 0x89); byte(e, 0xc2); /* mov edx, eax */
    byte(e, 0x83); byte(e, 0xc2); byte(e, (uint8_t)width); /* add edx, width */
    byte(e, 0x72); /* jc to try_mem0 (unsigned 32-bit wrap) */
    size_t patch_jc_stack = e->n++;

    byte(e, 0x3b); byte(e, 0x57); byte(e, offsetof(PwX86State, stack_high)); /* cmp edx, [rdi + stack_high] */
    byte(e, 0x76); /* jbe to fast_ok */
    size_t patch_jbe_stack = e->n++;

    /* try_mem0: check memory[0] if memory_count >= 1 */
    e->p[patch_jb_stack] = (uint8_t)(e->n - (patch_jb_stack + 1));
    e->p[patch_jc_stack] = (uint8_t)(e->n - (patch_jc_stack + 1));

    unsigned req_perm = write == 2 ? (PW_X86_READ|PW_X86_WRITE) : write ? PW_X86_WRITE : PW_X86_READ;
    byte(e, 0x83); byte(e, 0x7f); byte(e, offsetof(PwX86State, memory_count)); byte(e, 1); /* cmp dword [rdi + memory_count], 1 */
    byte(e, 0x72); /* jb to slow_path */
    size_t patch_jb_count = e->n++;

    byte(e, 0x8b); byte(e, 0x57); byte(e, offsetof(PwX86State, memory[0].permissions)); /* mov edx, [rdi + memory[0].permissions] */
    byte(e, 0x83); byte(e, 0xe2); byte(e, (uint8_t)req_perm); /* and edx, req_perm */
    byte(e, 0x83); byte(e, 0xfa); byte(e, (uint8_t)req_perm); /* cmp edx, req_perm */
    byte(e, 0x75); /* jne to slow_path */
    size_t patch_jne_perm = e->n++;

    byte(e, 0x3b); byte(e, 0x47); byte(e, offsetof(PwX86State, memory[0].low)); /* cmp eax, [rdi + memory[0].low] */
    byte(e, 0x72); /* jb to slow_path */
    size_t patch_jb_low = e->n++;

    /* The generic helper rejects malformed regions whose exclusive high
     * bound exceeds 4 GiB.  Keep the common (<4 GiB) case inline; a valid
     * region ending exactly at 4 GiB takes the slow path. */
    byte(e, 0x83); byte(e, 0x7f); byte(e, offsetof(PwX86State, memory[0].high) + 4);
    byte(e, 0); /* cmp dword [rdi + memory[0].high + 4], 0 */
    byte(e, 0x75); /* jne to slow_path */
    size_t patch_jne_high = e->n++;

    byte(e, 0x89); byte(e, 0xc2); /* mov edx, eax (zero-extends into RDX) */
    byte(e, 0x48); byte(e, 0x83); byte(e, 0xc2); byte(e, (uint8_t)width); /* add rdx, width (64-bit) */
    byte(e, 0x48); byte(e, 0x3b); byte(e, 0x57); byte(e, offsetof(PwX86State, memory[0].high)); /* cmp rdx, [rdi + memory[0].high] */
    byte(e, 0x76); /* jbe to fast_ok */
    size_t patch_jbe_mem = e->n++;

    /* slow_path: */
    e->p[patch_ja_count] = (uint8_t)(e->n - (patch_ja_count + 1));
    e->p[patch_jz_null] = (uint8_t)(e->n - (patch_jz_null + 1));
    e->p[patch_jb_count] = (uint8_t)(e->n - (patch_jb_count + 1));
    e->p[patch_jne_perm] = (uint8_t)(e->n - (patch_jne_perm + 1));
    e->p[patch_jb_low] = (uint8_t)(e->n - (patch_jb_low + 1));
    e->p[patch_jne_high] = (uint8_t)(e->n - (patch_jne_high + 1));

    byte(e,0x89);byte(e,0xc6); /* esi = address */
    byte(e,0xba);word(e,write);
    byte(e,0xb9);word(e,width);
    byte(e,0x57); /* push rdi */
    byte(e,0x41);byte(e,0x50); /* push r8 */
    byte(e,0x41);byte(e,0x51); /* push r9 */
    byte(e,0x41);byte(e,0x52); /* push r10 */
    byte(e,0x41);byte(e,0x53); /* push r11 */
    byte(e,0x48);byte(e,0xb8);
    uint64_t target=(uint64_t)(uintptr_t)&memory_pointer;
    word(e,(uint32_t)target);word(e,(uint32_t)(target>>32));
    byte(e,0xff);byte(e,0xd0); /* call rax */
    byte(e,0x41);byte(e,0x5b); /* pop r11 */
    byte(e,0x41);byte(e,0x5a); /* pop r10 */
    byte(e,0x41);byte(e,0x59); /* pop r9 */
    byte(e,0x41);byte(e,0x58); /* pop r8 */
    byte(e,0x5f); /* pop rdi */
    byte(e,0x48);byte(e,0x85);byte(e,0xc0);
    require_condition(e,0x75);

    /* fast_ok: */
    e->p[patch_jbe_stack] = (uint8_t)(e->n - (patch_jbe_stack + 1));
    e->p[patch_jbe_mem] = (uint8_t)(e->n - (patch_jbe_mem + 1));
}
static void memory_address(Emitter *e,unsigned write){memory_address_width(e,write,4);}
static int branch_condition(PwX86State *s,unsigned condition)
{
    unsigned f=s->eflags,of=!!(f&0x800),sf=!!(f&0x80),zf=!!(f&0x40),cf=f&1,pf=!!(f&4),answer;
    switch(condition>>1) {
    case 0:answer=of;break;case 1:answer=cf;break;case 2:answer=zf;break;
    case 3:answer=cf||zf;break;case 4:answer=sf;break;case 5:answer=pf;break;
    case 6:answer=sf!=of;break;default:answer=zf || sf!=of;break;
    }
    return (int)(answer^(condition&1));
}
static void condition_value(Emitter *e,unsigned condition)
{
    /* branch_condition is an ordinary SysV call.  Keep every host register
     * that may carry a resident guest value alive across it.  Five pushes
     * also preserve the required call-site stack alignment. */
    byte(e,0x57); /* push rdi */
    byte(e,0x41);byte(e,0x50); /* push r8 */
    byte(e,0x41);byte(e,0x51); /* push r9 */
    byte(e,0x41);byte(e,0x52); /* push r10 */
    byte(e,0x41);byte(e,0x53); /* push r11 */
    byte(e,0xbe);word(e,condition);byte(e,0x48);byte(e,0xb8);
    uint64_t fn=(uint64_t)(uintptr_t)&branch_condition;
    word(e,(uint32_t)fn);word(e,(uint32_t)(fn>>32));
    byte(e,0xff);byte(e,0xd0); /* call rax */
    byte(e,0x41);byte(e,0x5b); /* pop r11 */
    byte(e,0x41);byte(e,0x5a); /* pop r10 */
    byte(e,0x41);byte(e,0x59); /* pop r9 */
    byte(e,0x41);byte(e,0x58); /* pop r8 */
    byte(e,0x5f); /* pop rdi */
}
static inline int get_resident_host_reg(const PwX86RegContract *c, unsigned gpr)
{
    if (!c || gpr >= 8 || !(c->resident_mask & (1 << gpr))) return -1;
    return c->guest_to_host[gpr];
}

static inline unsigned popcount8(uint8_t m)
{
    unsigned count = 0;
    while (m) { count += (m & 1); m >>= 1; }
    return count;
}

static void emit_spill_dirty(Emitter *e, const PwX86RegContract *c)
{
    if (!c) return;
    for (unsigned g = 0; g < 8; g++) {
        if ((c->resident_mask & (1 << g)) && (c->dirty_mask & (1 << g))) {
            int h = c->guest_to_host[g];
            if (h >= 0 && h < PW_X86_MAX_HOST_REGS) {
                byte(e, 0x44); byte(e, 0x89);
                byte(e, (uint8_t)(0x47 | (h << 3)));
                byte(e, (uint8_t)(g * 4));
            }
        }
    }
}

__attribute__((unused))
static void emit_spill_single(Emitter *e, PwX86RegContract *c, unsigned gpr)
{
    if (!c || gpr >= 8 || !(c->resident_mask & (1 << gpr))) return;
    if (c->dirty_mask & (1 << gpr)) {
        int h = c->guest_to_host[gpr];
        if (h >= 0 && h < PW_X86_MAX_HOST_REGS) {
            byte(e, 0x44); byte(e, 0x89);
            byte(e, (uint8_t)(0x47 | (h << 3)));
            byte(e, (uint8_t)(gpr * 4));
            c->dirty_mask &= ~(1 << gpr);
        }
    }
}

static void emit_load_single(Emitter *e, const PwX86RegContract *c, unsigned gpr)
{
    if (!c || gpr >= 8 || !(c->resident_mask & (1 << gpr))) return;
    int h = c->guest_to_host[gpr];
    if (h >= 0 && h < PW_X86_MAX_HOST_REGS) {
        byte(e, 0x44); byte(e, 0x8b);
        byte(e, (uint8_t)(0x47 | (h << 3)));
        byte(e, (uint8_t)(gpr * 4));
    }
}

static void emit_load_all_resident(Emitter *e, const PwX86RegContract *c)
{
    if (!c) return;
    for (unsigned g = 0; g < 8; g++) {
        if (c->resident_mask & (1 << g)) {
            emit_load_single(e, c, g);
        }
    }
}

static void load_guest_reg(Emitter *e, const PwX86RegContract *c, unsigned gpr)
{
    int h = get_resident_host_reg(c, gpr);
    if (h >= 0) {
        byte(e, 0x44); byte(e, 0x89); byte(e, (uint8_t)(0xc0 | (h << 3)));
    } else {
        load_eax(e, gpr * 4);
    }
}

static void store_guest_reg(Emitter *e, PwX86RegContract *c, unsigned gpr)
{
    int h = get_resident_host_reg(c, gpr);
    if (h >= 0) {
        byte(e, 0x41); byte(e, 0x89); byte(e, (uint8_t)(0xc0 | h));
        if (c) c->dirty_mask |= (1 << gpr);
    } else {
        store_eax(e, gpr * 4);
    }
}

static void store_guest_imm(Emitter *e, PwX86RegContract *c, unsigned gpr, uint32_t val)
{
    int h = get_resident_host_reg(c, gpr);
    if (h >= 0) {
        byte(e, 0x41); byte(e, (uint8_t)(0xb8 + h)); word(e, val);
        if (c) c->dirty_mask |= (1 << gpr);
    } else {
        store(e, gpr * 4, val);
    }
}

__attribute__((unused))
static void load_guest_reg_edx(Emitter *e, const PwX86RegContract *c, unsigned gpr)
{
    int h = get_resident_host_reg(c, gpr);
    if (h >= 0) {
        byte(e, 0x44); byte(e, 0x89); byte(e, (uint8_t)(0xc2 | (h << 3)));
    } else {
        byte(e, 0x8b); byte(e, 0x57); byte(e, (uint8_t)(gpr * 4));
    }
}

static void load_guest_reg_ecx(Emitter *e, const PwX86RegContract *c, unsigned gpr)
{
    int h = get_resident_host_reg(c, gpr);
    if (h >= 0) {
        byte(e, 0x44); byte(e, 0x89); byte(e, (uint8_t)(0xc1 | (h << 3)));
    } else {
        byte(e, 0x8b); byte(e, 0x4f); byte(e, (uint8_t)(gpr * 4));
    }
}

static void store_guest_reg_edx(Emitter *e, PwX86RegContract *c, unsigned gpr)
{
    int h = get_resident_host_reg(c, gpr);
    if (h >= 0) {
        byte(e, 0x41); byte(e, 0x89); byte(e, (uint8_t)(0xd0 | h));
        if (c) c->dirty_mask |= (1 << gpr);
    } else {
        byte(e, 0x89); byte(e, 0x57); byte(e, (uint8_t)(gpr * 4));
    }
}

static void store_guest_reg_ecx(Emitter *e, PwX86RegContract *c, unsigned gpr)
{
    int h = get_resident_host_reg(c, gpr);
    if (h >= 0) {
        byte(e, 0x41); byte(e, 0x89); byte(e, (uint8_t)(0xc8 | h));
        if (c) c->dirty_mask |= (1 << gpr);
    } else {
        byte(e, 0x89); byte(e, 0x4f); byte(e, (uint8_t)(gpr * 4));
    }
}

__attribute__((unused))
static void load_guest_reg16(Emitter *e, const PwX86RegContract *c, unsigned gpr)
{
    int h = get_resident_host_reg(c, gpr);
    if (h >= 0) {
        byte(e, 0x66); byte(e, 0x44); byte(e, 0x89); byte(e, (uint8_t)(0xc0 | (h << 3)));
    } else {
        byte(e, 0x66); byte(e, 0x8b); byte(e, 0x47); byte(e, (uint8_t)(gpr * 4));
    }
}

__attribute__((unused))
static void store_guest_reg16(Emitter *e, PwX86RegContract *c, unsigned gpr)
{
    int h = get_resident_host_reg(c, gpr);
    if (h >= 0) {
        byte(e, 0x66); byte(e, 0x41); byte(e, 0x89); byte(e, (uint8_t)(0xc0 | h));
        if (c) c->dirty_mask |= (1 << gpr);
    } else {
        byte(e, 0x66); byte(e, 0x89); byte(e, 0x47); byte(e, (uint8_t)(gpr * 4));
    }
}

__attribute__((unused))
static void store_guest_reg8_low(Emitter *e, PwX86RegContract *c, unsigned gpr)
{
    int h = get_resident_host_reg(c, gpr);
    if (h >= 0) {
        byte(e, 0x41); byte(e, 0x88); byte(e, (uint8_t)(0xc0 | h));
        if (c) c->dirty_mask |= (1 << gpr);
    } else {
        byte(e, 0x88); byte(e, 0x47); byte(e, (uint8_t)(gpr * 4));
    }
}

static void emit_chain_exit(Emitter *e, uint32_t count, uint32_t target_pc,
                            const PwX86RegContract *contract,
                            size_t *patch_offset, size_t *stub_offset,
                            size_t *reconcile_offset, size_t *reconcile_patch_offset)
{
    uint8_t n_dirty = contract ? popcount8(contract->dirty_mask) : 0;

    /* 1. add dword ptr [rdi + step_retired], count */
    byte(e, 0x83); byte(e, 0x47); byte(e, offsetof(PwX86State, step_retired)); byte(e, (uint8_t)count);
    /* 2. dec dword ptr [rdi + chain_budget] */
    byte(e, 0xff); byte(e, 0x4f); byte(e, offsetof(PwX86State, chain_budget));
    /* 3. jz safepoint */
    byte(e, 0x74);
    size_t safepoint_patch = e->n++;
    /* 4. inc dword ptr [rdi + step_transitions] */
    byte(e, 0xff); byte(e, 0x47); byte(e, offsetof(PwX86State, step_transitions));
    /* 5. movabs $0, %r11 (10 bytes: 49 bb <8 bytes>) */
    byte(e, 0x49); byte(e, 0xbb);
    *patch_offset = e->n;
    for (int i = 0; i < 8; i++) byte(e, 0);
    /* 6. test %r11, %r11 (3 bytes: 4d 85 db) */
    byte(e, 0x4d); byte(e, 0x85); byte(e, 0xdb);
    /* 7. jz unlinked_stub */
    byte(e, 0x74);
    size_t unlinked_patch = e->n++;
    /* 8. jmp *(%r11) (3 bytes: 41 ff 23) */
    byte(e, 0x41); byte(e, 0xff); byte(e, 0x23);

    /* 9. safepoint_exit: */
    e->p[safepoint_patch] = (uint8_t)(e->n - (safepoint_patch + 1));
    emit_spill_dirty(e, contract);
    if (n_dirty) {
        byte(e, 0x83); byte(e, 0x47); byte(e, offsetof(PwX86State, reg_stores)); byte(e, n_dirty);
    }
    byte(e, 0x48); byte(e, 0xc7); byte(e, 0x47); byte(e, offsetof(PwX86State, last_exit_slot));
    word(e, 0);
    /* jmp common_exit */
    byte(e, 0xeb);
    size_t safepoint_common_patch = e->n++;

    /* 10. unlinked_stub: */
    *stub_offset = e->n;
    e->p[unlinked_patch] = (uint8_t)(e->n - (unlinked_patch + 1));
    emit_spill_dirty(e, contract);
    if (n_dirty) {
        byte(e, 0x83); byte(e, 0x47); byte(e, offsetof(PwX86State, reg_stores)); byte(e, n_dirty);
    }
    byte(e, 0x4c); byte(e, 0x89); byte(e, 0x5f); byte(e, offsetof(PwX86State, last_exit_slot));

    /* 11. common_exit: */
    e->p[safepoint_common_patch] = (uint8_t)(e->n - (safepoint_common_patch + 1));
    store(e, offsetof(PwX86State, eip), target_pc);
    byte(e, 0x31); byte(e, 0xc0); byte(e, 0xc3); /* xor eax, eax; ret */

    /* 12. reconcile_stub: jumped to when linked block has different contract */
    *reconcile_offset = e->n;
    emit_spill_dirty(e, contract);
    if (n_dirty) {
        byte(e, 0x83); byte(e, 0x47); byte(e, offsetof(PwX86State, reg_spills)); byte(e, n_dirty);
    }
    /* inc dword ptr [rdi + reg_reconciliations] */
    byte(e, 0xff); byte(e, 0x47); byte(e, offsetof(PwX86State, reg_reconciliations));
    /* movabs $link_slot->canonical_code, %r11 */
    byte(e, 0x49); byte(e, 0xbb);
    *reconcile_patch_offset = e->n;
    for (int i = 0; i < 8; i++) byte(e, 0);
    /* jmp *(%r11) */
    byte(e, 0x41); byte(e, 0xff); byte(e, 0x23);
}

static void emit_materialize_flags(Emitter *e, uint32_t mask);
static uint32_t branch_condition_flags(unsigned condition);

static void conditional_target(Emitter *e, unsigned condition, uint32_t next, uint32_t target,
                               PwX86Block *block, uint32_t count)
{
    unsigned c = condition >> 1;
    unsigned invert = condition & 1;
    uint8_t jump_op = invert ? 0x84 : 0x85;
    size_t branch_patch = 0;
    emit_materialize_flags(e,branch_condition_flags(condition));
    if (c == 0) { /* OF: bit 11 in eflags (bit 3 of byte [rdi+53]) */
        byte(e,0xf6);byte(e,0x47);byte(e,offsetof(PwX86State,eflags)+1);byte(e,0x08);
        byte(e,0x0f);byte(e,jump_op); branch_patch = e->n; word(e, 0);
    } else if (c == 1) { /* CF: bit 0 in eflags (byte [rdi+52]) */
        byte(e,0xf6);byte(e,0x47);byte(e,offsetof(PwX86State,eflags));byte(e,0x01);
        byte(e,0x0f);byte(e,jump_op); branch_patch = e->n; word(e, 0);
    } else if (c == 2) { /* ZF: bit 6 in eflags (byte [rdi+52]) */
        byte(e,0xf6);byte(e,0x47);byte(e,offsetof(PwX86State,eflags));byte(e,0x40);
        byte(e,0x0f);byte(e,jump_op); branch_patch = e->n; word(e, 0);
    } else if (c == 3) { /* CF || ZF: bits 0, 6 in eflags (byte [rdi+52]) */
        byte(e,0xf6);byte(e,0x47);byte(e,offsetof(PwX86State,eflags));byte(e,0x41);
        byte(e,0x0f);byte(e,jump_op); branch_patch = e->n; word(e, 0);
    } else if (c == 4) { /* SF: bit 7 in eflags (byte [rdi+52]) */
        byte(e,0xf6);byte(e,0x47);byte(e,offsetof(PwX86State,eflags));byte(e,0x80);
        byte(e,0x0f);byte(e,jump_op); branch_patch = e->n; word(e, 0);
    } else if (c == 5) { /* PF: bit 2 in eflags (byte [rdi+52]) */
        byte(e,0xf6);byte(e,0x47);byte(e,offsetof(PwX86State,eflags));byte(e,0x04);
        byte(e,0x0f);byte(e,jump_op); branch_patch = e->n; word(e, 0);
    } else {
        condition_value(e,condition);
        byte(e,0x85);byte(e,0xc0);
        byte(e,0x0f);byte(e,0x85); branch_patch = e->n; word(e, 0);
    }
    emit_chain_exit(e, count, next, &block->exit_contract,
                    &block->exit.fallthrough_patch_offset, &block->exit.fallthrough_stub_offset,
                    &block->exit.fallthrough_reconcile_offset, &block->exit.fallthrough_reconcile_patch_offset);
    uint32_t disp = (uint32_t)(e->n - (branch_patch + 4));
    e->p[branch_patch] = (uint8_t)disp;
    e->p[branch_patch+1] = (uint8_t)(disp >> 8);
    e->p[branch_patch+2] = (uint8_t)(disp >> 16);
    e->p[branch_patch+3] = (uint8_t)(disp >> 24);
    emit_chain_exit(e, count, target, &block->exit_contract,
                    &block->exit.target_patch_offset, &block->exit.target_stub_offset,
                    &block->exit.target_reconcile_offset, &block->exit.target_reconcile_patch_offset);
}

static void stack_address(Emitter *e, int push, const PwX86RegContract *c)
{
    load_guest_reg(e, c, 4);
    if (push) {
        /* Check before subtracting: an ESP of 0 must not wrap. */
        byte(e,0x83); byte(e,0xf8); byte(e,4);
        require_condition(e,0x73); /* jae */
        byte(e,0x83); byte(e,0xe8); byte(e,4);
    }
    stack_bounds(e);
}
typedef struct Operand {
    unsigned reg, rm, mod, scale;
    int base, index;
    uint32_t displacement;
    size_t bytes;
} Operand;
static int decode_operand(const uint8_t *p, size_t n, Operand *o)
{
    if (!n) return PW_ERR_TRUNCATED;
    memset(o,0,sizeof(*o));
    o->mod=p[0]>>6; o->reg=(p[0]>>3)&7; o->rm=p[0]&7;
    o->base=(int)o->rm; o->index=-1; o->bytes=1;
    if (o->mod==3) return PW_OK;
    unsigned displacement=o->mod==1 ? 1 : o->mod==2 ? 4 : 0;
    if (o->rm==4) {
        if (n<2) return PW_ERR_TRUNCATED;
        o->bytes=2; o->scale=p[1]>>6;
        o->index=(p[1]>>3)&7; o->base=p[1]&7;
        if (o->index==4) o->index=-1;
    }
    if (o->mod==0 && o->base==5) { o->base=-1; displacement=4; }
    if (n-o->bytes < displacement) return PW_ERR_TRUNCATED;
    if (displacement==1) o->displacement=(uint32_t)(int32_t)(int8_t)p[o->bytes];
    else if (displacement==4) o->displacement=read32(p+o->bytes);
    o->bytes+=displacement;
    return PW_OK;
}
static void effective_address(Emitter *e, const Operand *o, const PwX86RegContract *c)
{
    /* EAX arithmetic deliberately wraps at 32 bits; never RIP-relative. */
    byte(e,0xb8); word(e,o->displacement);
    if (o->base>=0) {
        int h = get_resident_host_reg(c, (unsigned)o->base);
        if (h >= 0) {
            byte(e, 0x41); byte(e, 0x03); byte(e, (uint8_t)(0xc0 | h));
        } else {
            byte(e,0x03); byte(e,0x47); byte(e,(uint8_t)(o->base*4));
        }
    }
    if (o->index>=0) {
        int h = get_resident_host_reg(c, (unsigned)o->index);
        if (h >= 0) {
            byte(e, 0x41); byte(e, 0x8b); byte(e, (uint8_t)(0xd0 | h));
        } else {
            byte(e,0x8b); byte(e,0x57); byte(e,(uint8_t)(o->index*4));
        }
        byte(e,0xc1); byte(e,0xe2); byte(e,(uint8_t)o->scale);
        byte(e,0x01); byte(e,0xd0);
    }
}
static void push_imm(Emitter *e, uint32_t value, PwX86RegContract *c)
{
    stack_address(e, 1, c);
    byte(e,0xc7); byte(e,0x00); word(e,value); /* mov dword [rax],imm32 */
    store_guest_reg(e, c, 4);
}
static void success(Emitter *e)
{
    byte(e,0x31); byte(e,0xc0); byte(e,0xc3);
}
uint32_t pw_x86_compute_canonical_flags(const PwX86DeferredFlags *df, uint32_t prev_eflags)
{
    if (!df) return prev_eflags;
    return (prev_eflags & ~df->known_mask) |
           (df->raw_flags & df->known_mask);
}

void pw_x86_materialize_flag_bits(PwX86State *state, uint32_t demand_mask)
{
    uint32_t mask = demand_mask & state->deferred_flags.known_mask;
    state->eflags = (state->eflags & ~mask) |
                    (state->deferred_flags.raw_flags & mask);
}

void pw_x86_commit_canonical_flags(PwX86State *state)
{
    if (!state->deferred_flags.known_mask) return;
    state->eflags = pw_x86_compute_canonical_flags(&state->deferred_flags, state->eflags);
    state->deferred_flags.known_mask = 0;
}

static void emit_materialize_flags(Emitter *e,uint32_t mask)
{
    if(!mask)return;
    /* Merge only demanded pending bits into canonical guest EFLAGS.  This is
     * branch-free and does not cross the C ABI, so resident r8-r10 survive. */
    load_eax(e,offsetof(PwX86State,eflags));
    byte(e,0x8b);byte(e,0x97);
    word(e,(uint32_t)offsetof(PwX86State,deferred_flags.known_mask));
    byte(e,0x81);byte(e,0xe2);word(e,mask);
    byte(e,0x8b);byte(e,0x8f);word(e,(uint32_t)offsetof(PwX86State,deferred_flags.raw_flags));
    byte(e,0x31);byte(e,0xc1); /* ecx = raw ^ canonical */
    byte(e,0x21);byte(e,0xd1); /* retain changed demanded bits */
    byte(e,0x31);byte(e,0xc8); /* merge into eax */
    store_eax(e,offsetof(PwX86State,eflags));
}

static void emit_commit_flags(Emitter *e)
{
    emit_materialize_flags(e,0x8d5);
    byte(e,0xc7);byte(e,0x87);
    word(e,(uint32_t)offsetof(PwX86State,deferred_flags.known_mask));word(e,0);
}

static void save_arithmetic_flags(Emitter *e,uint32_t mask)
{
    /* Snapshot before any emitter bookkeeping changes flags. Native RSP is
     * balanced; guest control flags (DF/IF/etc.) are never loaded into RFLAGS. */
    byte(e,0x9c); byte(e,0x59); /* pushfq; pop rcx */
    byte(e,0x81); byte(e,0xe1); word(e,mask);
    byte(e,0x8b); byte(e,0x57); byte(e,offsetof(PwX86State,eflags));
    byte(e,0x81); byte(e,0xe2); word(e,~mask);
    byte(e,0x09); byte(e,0xca);
    byte(e,0x89); byte(e,0x57); byte(e,offsetof(PwX86State,eflags));
}

static void load_edx_disp32(Emitter *e,size_t offset)
{
    byte(e,0x8b);byte(e,0x97);word(e,(uint32_t)offset);
}

static void store_edx_disp32(Emitter *e,size_t offset)
{
    byte(e,0x89);byte(e,0x97);word(e,(uint32_t)offset);
}

static void store_imm_disp32(Emitter *e,size_t offset,uint32_t value)
{
    byte(e,0xc7);byte(e,0x87);word(e,(uint32_t)offset);word(e,value);
}

static void defer_arithmetic_flags(Emitter *e,uint32_t mask)
{
    const size_t result_offset=offsetof(PwX86State,deferred_flags.raw_flags);
    const size_t known_offset=offsetof(PwX86State,deferred_flags.known_mask);

    byte(e,0x9c);byte(e,0x59);                 /* pushfq; pop rcx */
    if(mask==0x8d5) {
        /* Every deferred arithmetic bit is replaced, so no merge is needed. */
        byte(e,0x89);byte(e,0x8f);word(e,(uint32_t)result_offset);
        store_imm_disp32(e,known_offset,mask);
    } else {
        byte(e,0x81);byte(e,0xe1);word(e,mask); /* and ecx, mask */
        load_edx_disp32(e,result_offset);
        byte(e,0x81);byte(e,0xe2);word(e,~mask);
        byte(e,0x09);byte(e,0xca);
        store_edx_disp32(e,result_offset);
        byte(e,0x81);byte(e,0x8f);word(e,(uint32_t)known_offset);word(e,mask);
    }
}

static void emit_save_flags(Emitter *e, uint32_t mask, unsigned lazy_flags_enabled,
                            int flags_dead)
{
    if (flags_dead) return;
    if (!lazy_flags_enabled)
        save_arithmetic_flags(e, mask);
    else
        defer_arithmetic_flags(e,mask);
}
static void fs_address(Emitter *e, uint32_t offset)
{
    /* Check offset <= size-4 without wraparound. */
    load_eax(e,offsetof(PwX86State,fs_bytes));
    byte(e,0x83); byte(e,0xf8); byte(e,4); require_condition(e,0x73);
    byte(e,0x83); byte(e,0xe8); byte(e,4);
    byte(e,0x3d); word(e,offset); require_condition(e,0x73);
    load_eax(e,offsetof(PwX86State,fs_base));
    byte(e,0x05); word(e,offset); require_condition(e,0x73); /* no carry */
    /* The last byte of the dword must remain in the 32-bit address space. */
    byte(e,0x3d); word(e,0xfffffffcu); require_condition(e,0x76);
}
static int x87_dispatch(PwX86State *state,unsigned action,uintptr_t operand)
{
    uint16_t ax=0;int status=pw_x87_execute(&state->fp,(PwX87Action)action,operand,&ax);
    if(status==PW_OK && action==PW_X87_FNSTSW_AX)
        state->gpr[0]=(state->gpr[0]&0xffff0000u)|ax;
    return status;
}
static void x87_call(Emitter *e,unsigned action,unsigned register_operand)
{
    if(register_operand){byte(e,0xba);word(e,register_operand-1);}
    else {byte(e,0x48);byte(e,0x89);byte(e,0xc2);}
    byte(e,0xbe);word(e,action);byte(e,0x57);byte(e,0x48);byte(e,0xb8);
    uint64_t target=(uint64_t)(uintptr_t)&x87_dispatch;
    word(e,(uint32_t)target);word(e,(uint32_t)(target>>32));
    byte(e,0xff);byte(e,0xd0);byte(e,0x5f);byte(e,0x85);byte(e,0xc0);
    byte(e,0x74);byte(e,1);byte(e,0xc3); /* propagate helper failure */
}
static int string_dispatch(PwX86State *state,unsigned opcode,unsigned width,unsigned repeat)
{
    if(!state || (width!=1 && width!=2 && width!=4) ||
       !((opcode>=0xa4 && opcode<=0xa7) || opcode==0xaa || opcode==0xab))
        return PW_ERR_PRECONDITION;
    uint32_t count=repeat?state->gpr[1]:1;
    if(!count)return PW_OK;
    uint64_t span=(uint64_t)count*width;
    if(span>0x100000000ull)return PW_ERR_VM;
    unsigned backwards=!!(state->eflags&0x400);uint32_t destination=state->gpr[7],source=state->gpr[6];
    uint32_t dst_low=destination;
    if(backwards) {
        uint64_t retreat=(uint64_t)(count-1)*width;
        if(retreat>destination)return PW_ERR_VM;
        dst_low=destination-(uint32_t)retreat;
    } else if((uint64_t)destination+span>0x100000000ull)return PW_ERR_VM;
    unsigned moving=opcode==0xa4 || opcode==0xa5;
    unsigned comparing=opcode==0xa6 || opcode==0xa7;
    if(!memory_range_pointer(state,dst_low,comparing?0:1,span))return PW_ERR_VM;
    uint32_t src_low=source;
    if(moving || comparing) {
        if(backwards) {
            uint64_t retreat=(uint64_t)(count-1)*width;
            if(retreat>source)return PW_ERR_VM;
            src_low=source-(uint32_t)retreat;
        } else if((uint64_t)source+span>0x100000000ull)return PW_ERR_VM;
        if(!memory_range_pointer(state,src_low,0,span))return PW_ERR_VM;
    }
    for(uint32_t i=0;i<count;i++) {
        uint32_t offset=i*width;
        uint32_t dst=backwards?destination-offset:destination+offset;
        if(moving) {
            uint32_t src=backwards?source-offset:source+offset;
            memmove((void *)(uintptr_t)dst,(const void *)(uintptr_t)src,width);
        } else if(comparing) {
            uint32_t src=backwards?source-offset:source+offset,left=0,right=0;
            memcpy(&left,(const void *)(uintptr_t)src,width);
            memcpy(&right,(const void *)(uintptr_t)dst,width);
            uint32_t mask=width==4?UINT32_MAX:(UINT32_C(1)<<(width*8))-1;
            uint32_t sign=UINT32_C(1)<<(width*8-1),result=(left-right)&mask;
            uint32_t flags=(left<right?1u:0u)|(result==0?0x40u:0u)|
                (result&sign?0x80u:0u)|((left^right^result)&0x10u)|
                (((left^right)&(left^result)&sign)?0x800u:0u);
            unsigned parity=0;for(unsigned bit=0;bit<8;bit++)parity^=(result>>bit)&1u;
            if(!parity)flags|=4;
            state->eflags=(state->eflags&~0x8d5u)|(flags&0x8d5u);
            if(repeat && result) {
                count=i+1;
                break;
            }
        } else memcpy((void *)(uintptr_t)dst,&state->gpr[0],width);
    }
    uint32_t delta=count*width;
    state->gpr[7]=backwards?destination-delta:destination+delta;
    if(moving || comparing)state->gpr[6]=backwards?source-delta:source+delta;
    if(repeat)state->gpr[1]-=count;
    return PW_OK;
}
static void string_call(Emitter *e,unsigned opcode,unsigned width,unsigned repeat)
{
    byte(e,0xbe);word(e,opcode);byte(e,0xba);word(e,width);byte(e,0xb9);word(e,repeat);
    byte(e,0x57);byte(e,0x48);byte(e,0xb8);
    uint64_t target=(uint64_t)(uintptr_t)&string_dispatch;
    word(e,(uint32_t)target);word(e,(uint32_t)(target>>32));
    byte(e,0xff);byte(e,0xd0);byte(e,0x5f);byte(e,0x85);byte(e,0xc0);
    byte(e,0x74);byte(e,1);byte(e,0xc3);
}
static int muldiv_dispatch(PwX86State *state,unsigned action,uint32_t operand)
{
    if(!state || action<4 || action>7)return PW_ERR_PRECONDITION;
    uint32_t eax=state->gpr[0],edx=state->gpr[2],result_eax=0,result_edx=0;
    unsigned overflow=0;
    if(action==4) {
        uint64_t product=(uint64_t)eax*operand;
        result_eax=(uint32_t)product;result_edx=(uint32_t)(product>>32);
        overflow=result_edx!=0;
    } else if(action==5) {
        int64_t product=(int64_t)(int32_t)eax*(int32_t)operand;
        result_eax=(uint32_t)product;result_edx=(uint32_t)((uint64_t)product>>32);
        overflow=product<(int64_t)INT32_MIN || product>(int64_t)INT32_MAX;
    } else if(action==6) {
        if(!operand)return PW_ERR_VM;
        uint64_t dividend=((uint64_t)edx<<32)|eax;
        uint64_t quotient=dividend/operand;
        if(quotient>UINT32_MAX)return PW_ERR_VM;
        result_eax=(uint32_t)quotient;result_edx=(uint32_t)(dividend%operand);
    } else {
        int32_t divisor=(int32_t)operand;
        if(!divisor)return PW_ERR_VM;
        uint64_t bits=((uint64_t)edx<<32)|eax;int64_t dividend;
        memcpy(&dividend,&bits,sizeof(dividend));
        if(dividend==INT64_MIN && divisor==-1)return PW_ERR_VM;
        int64_t quotient=dividend/divisor;
        if(quotient<INT32_MIN || quotient>INT32_MAX)return PW_ERR_VM;
        result_eax=(uint32_t)(int32_t)quotient;
        result_edx=(uint32_t)(int32_t)(dividend%divisor);
    }
    state->gpr[0]=result_eax;state->gpr[2]=result_edx;
    if(action<6) {
        state->eflags&=~0x801u;
        if(overflow)state->eflags|=0x801u;
    }
    return PW_OK;
}
static void muldiv_call(Emitter *e,unsigned action)
{
    byte(e,0x89);byte(e,0xc2);byte(e,0xbe);word(e,action);
    byte(e,0x57);byte(e,0x48);byte(e,0xb8);
    uint64_t target=(uint64_t)(uintptr_t)&muldiv_dispatch;
    word(e,(uint32_t)target);word(e,(uint32_t)(target>>32));
    byte(e,0xff);byte(e,0xd0);byte(e,0x5f);byte(e,0x85);byte(e,0xc0);
    byte(e,0x74);byte(e,1);byte(e,0xc3);
}

static uint32_t branch_condition_flags(unsigned condition)
{
    switch ((condition >> 1) & 7) {
        case 0: return 0x800; /* OF */
        case 1: return 0x001; /* CF */
        case 2: return 0x040; /* ZF */
        case 3: return 0x041; /* CF | ZF */
        case 4: return 0x080; /* SF */
        case 5: return 0x004; /* PF */
        case 6: return 0x880; /* SF | OF */
        case 7: return 0x8c0; /* SF | OF | ZF */
        default: return 0x8d5;
    }
}

typedef struct DecodedInst {
    size_t cursor;
    size_t length;
    uint8_t op;
    Operand operand;
    unsigned compare;
    unsigned alu;
    unsigned short_imm;
    unsigned word_operand;
    unsigned conditional;
    unsigned extend;
    unsigned setcc;
    unsigned extend_word_destination;
    unsigned x87, x87_width, x87_write, x87_register;
    unsigned string_op, string_width, string_repeat;
    unsigned word_general;
    unsigned byte_alu, byte_direction;
    unsigned imul_general;
    int terminal;
    uint32_t flags_def;
    uint32_t flags_use;
    int flags_dead;
    int can_fault;
} DecodedInst;

int pw_x86_translate_ext(const uint8_t *source, size_t bytes, uint32_t pc,
                         uint8_t *output, size_t capacity, PwX86Block *block,
                         unsigned residency_enabled, unsigned lazy_flags_enabled)
{
    Emitter e = {output,0,capacity,0};
    size_t cursor = 0;
    unsigned count = 0;
    if (!source || !bytes || !output || !capacity || !block)
        return PW_ERR_PRECONDITION;
    memset(block,0,sizeof(*block));

    DecodedInst insts[32];
    memset(insts, 0, sizeof(insts));
    unsigned gpr_uses[8] = {0};

#define DECODE_FAIL(err) do { if (count) goto analyze_and_emit; return (err); } while (0)

    /* Pass 1: Instruction boundary and semantic decode */
    while (cursor < bytes && count < 32) {
        DecodedInst *d = &insts[count];
        d->cursor = cursor;
        const uint8_t op = source[cursor];
        d->op = op;
        d->alu = 7;
        size_t length = 0;
        Operand operand;
        memset(&operand, 0, sizeof(operand));
        unsigned compare=0,alu=7,short_imm=0,word_operand=0,conditional=0,extend=0,setcc=0;
        unsigned extend_word_destination=0;
        unsigned x87=0,x87_width=0,x87_write=0,x87_register=0;
        unsigned string_op=0,string_width=0,string_repeat=0;
        unsigned word_general=0;
        unsigned byte_alu=0,byte_direction=0;
        unsigned imul_general=0;
        int terminal = 0;
        uint32_t flags_def = 0, flags_use = 0;
        int can_fault = 0;

        if(op==0x66 && bytes-cursor>=2 && source[cursor+1]==0xf3) {
            if(bytes-cursor<3)DECODE_FAIL(PW_ERR_TRUNCATED);
            if(source[cursor+2]!=0xa5 && source[cursor+2]!=0xab)DECODE_FAIL(PW_ERR_UNSUPPORTED);
            string_op=source[cursor+2];string_width=2;string_repeat=1;length=3;can_fault=1;
        } else if(op==0xf3) {
            if(bytes-cursor<2)DECODE_FAIL(PW_ERR_TRUNCATED);
            if((source[cursor+1]<0xa4 || source[cursor+1]>0xa7) &&
               source[cursor+1]!=0xaa && source[cursor+1]!=0xab)
                DECODE_FAIL(PW_ERR_UNSUPPORTED);
            string_op=source[cursor+1];string_width=(string_op&1)?4:1;
            string_repeat=1;length=2;can_fault=1;
        } else if((op>=0xa4 && op<=0xa7) || op==0xaa || op==0xab) {
            string_op=op;string_width=(op&1)?4:1;length=1;can_fault=1;
        } else if(op==0x66 && bytes-cursor>=2 &&
                  (source[cursor+1]==0xa5 || source[cursor+1]==0xab)) {
            string_op=source[cursor+1];string_width=2;length=2;can_fault=1;
        } else if(op==0x66 && bytes-cursor==2 && source[cursor+1]==0x0f) {
            DECODE_FAIL(PW_ERR_TRUNCATED);
        } else if(op==0x66 && bytes-cursor>=3 && source[cursor+1]==0x0f &&
                  (source[cursor+2]==0xb6 || source[cursor+2]==0xb7 ||
                   source[cursor+2]==0xbe || source[cursor+2]==0xbf)) {
            int result=decode_operand(source+cursor+3,bytes-cursor-3,&operand);
            if(result!=PW_OK)DECODE_FAIL(result);
            extend=1;extend_word_destination=1;length=3+operand.bytes;can_fault=(operand.mod!=3);
        } else if(op==0x66 && bytes-cursor>=2 &&
                  (source[cursor+1]==0x01 || source[cursor+1]==0x03 ||
                   source[cursor+1]==0x09 || source[cursor+1]==0x0b ||
                   source[cursor+1]==0x11 || source[cursor+1]==0x13 ||
                   source[cursor+1]==0x19 || source[cursor+1]==0x1b ||
                   source[cursor+1]==0x21 || source[cursor+1]==0x23 ||
                   source[cursor+1]==0x29 || source[cursor+1]==0x2b ||
                   source[cursor+1]==0x31 || source[cursor+1]==0x33 ||
                   source[cursor+1]==0x89 || source[cursor+1]==0x8b ||
                   source[cursor+1]==0x39 || source[cursor+1]==0x3b ||
                   source[cursor+1]==0x85 || source[cursor+1]==0xc7)) {
            word_general=source[cursor+1];
            int result=decode_operand(source+cursor+2,bytes-cursor-2,&operand);
            if(result!=PW_OK)DECODE_FAIL(result);
            if(word_general==0xc7 && operand.reg)DECODE_FAIL(PW_ERR_UNSUPPORTED);
            length=2+operand.bytes+(word_general==0xc7?2:0);
            can_fault=(operand.mod!=3);
            unsigned alu_word=word_general<=0x33 && ((word_general&7)==1 || (word_general&7)==3);
            unsigned compare_word=word_general==0x39 || word_general==0x3b;
            unsigned test_word=word_general==0x85;
            if(alu_word) {
                unsigned op_w=word_general>>3;
                unsigned log_w=op_w==1||op_w==4||op_w==6;
                flags_def=log_w?0x8c5:0x8d5;
                if(op_w==2||op_w==3)flags_use=0x001;
            } else if(compare_word) flags_def=0x8d5;
            else if(test_word) flags_def=0x8c5;
        } else if(op>=0xd8 && op<=0xdf) {
            int result=decode_operand(source+cursor+1,bytes-cursor-1,&operand);
            if(result!=PW_OK)DECODE_FAIL(result);
            length=1+operand.bytes;can_fault=(operand.mod!=3);
            if(operand.mod!=3) {
                if(op==0xd9 && operand.reg==0){x87=PW_X87_FLD_F32+1;x87_width=4;}
                else if(op==0xd9 && operand.reg==2){x87=PW_X87_FST_F32+1;x87_width=4;x87_write=1;}
                else if(op==0xd9 && operand.reg==3){x87=PW_X87_FSTP_F32+1;x87_width=4;x87_write=1;}
                else if(op==0xdd && operand.reg==0){x87=PW_X87_FLD_F64+1;x87_width=8;}
                else if(op==0xdd && operand.reg==2){x87=PW_X87_FST_F64+1;x87_width=8;x87_write=1;}
                else if(op==0xdd && operand.reg==3){x87=PW_X87_FSTP_F64+1;x87_width=8;x87_write=1;}
                else if(op==0xdb && operand.reg==0){x87=PW_X87_FILD_I32+1;x87_width=4;}
                else if(op==0xd8) {
                    static const unsigned actions[]={PW_X87_FADD_F32,PW_X87_FMUL_F32,
                        PW_X87_FCOM_F32,PW_X87_FCOMP_F32,PW_X87_FSUB_F32,
                        PW_X87_FSUBR_F32,PW_X87_FDIV_F32,PW_X87_FDIVR_F32};
                    x87=actions[operand.reg]+1;x87_width=4;
                } else if(op==0xdc) {
                    static const unsigned actions[]={PW_X87_FADD_F64,PW_X87_FMUL_F64,
                        PW_X87_FCOM_F64,PW_X87_FCOMP_F64,PW_X87_FSUB_F64,
                        PW_X87_FSUBR_F64,PW_X87_FDIV_F64,PW_X87_FDIVR_F64};
                    x87=actions[operand.reg]+1;x87_width=8;
                }
                else DECODE_FAIL(PW_ERR_UNSUPPORTED);
            } else if(op==0xd9 && operand.reg==0) {
                x87=PW_X87_FLD_ST+1;x87_register=operand.rm+1;
            } else if(op==0xd9 && operand.reg==5 && operand.rm==0)x87=PW_X87_FLD1+1;
            else if(op==0xd9 && operand.reg==5 && operand.rm==6)x87=PW_X87_FLDZ+1;
            else if(op==0xd9 && operand.reg==4 && operand.rm==0)x87=PW_X87_FCHS+1;
            else if(op==0xd9 && operand.reg==4 && operand.rm==1)x87=PW_X87_FABS+1;
            else if(op==0xd9 && operand.reg==7 && operand.rm==2)x87=PW_X87_FSQRT+1;
            else if(op==0xd9 && operand.reg==7 && operand.rm==6)x87=PW_X87_FSIN+1;
            else if(op==0xd9 && operand.reg==7 && operand.rm==7)x87=PW_X87_FCOS+1;
            else if(op==0xdd && operand.reg==2) {
                x87=PW_X87_FST_ST+1;x87_register=operand.rm+1;
            } else if(op==0xdd && operand.reg==3) {
                x87=PW_X87_FSTP_ST+1;x87_register=operand.rm+1;
            } else if(op==0xdf && operand.reg==4 && operand.rm==0)x87=PW_X87_FNSTSW_AX+1;
            else if(op==0xd8 && (operand.reg==0 || operand.reg==1 || operand.reg==2 ||
                                 operand.reg==3 || operand.reg==4 || operand.reg==5 ||
                                 operand.reg==6)) {
                static const unsigned actions[]={PW_X87_FADD_ST,PW_X87_FMUL_ST,
                    PW_X87_FCOM_ST,PW_X87_FCOMP_ST,PW_X87_FSUB_ST,
                    PW_X87_FSUBR_ST,PW_X87_FDIV_ST};
                x87=actions[operand.reg]+1;x87_register=operand.rm+1;
            } else if(op==0xde && (operand.reg==0 || operand.reg==1 ||
                                   operand.reg==5 || operand.reg==6 || operand.reg==7)) {
                x87=(operand.reg==0?PW_X87_FADDP_ST:
                    operand.reg==1?PW_X87_FMULP_ST:
                    operand.reg==5?PW_X87_FSUBP_ST:
                    operand.reg==6?PW_X87_FDIVRP_ST:PW_X87_FDIVP_ST)+1;
                x87_register=operand.rm+1;
            } else if(op==0xda && operand.reg==5 && operand.rm==1)x87=PW_X87_FUCOMPP+1;
            else if(op==0xde && operand.reg==3 && operand.rm==1)x87=PW_X87_FCOMPP+1;
            else if(op==0xdc && (operand.reg==0 || operand.reg==1 || operand.reg>=4)) {
                static const unsigned actions[]={PW_X87_FADD_TO_ST,PW_X87_FMUL_TO_ST,0,0,
                    PW_X87_FSUBR_TO_ST,PW_X87_FSUB_TO_ST,
                    PW_X87_FDIVR_TO_ST,PW_X87_FDIV_TO_ST};
                x87=actions[operand.reg]+1;x87_register=operand.rm+1;
            }
            else DECODE_FAIL(PW_ERR_UNSUPPORTED);
        } else if(op==0xc1 || op==0xd1 || op==0xd3) {
            int result=decode_operand(source+cursor+1,bytes-cursor-1,&operand);
            if(result!=PW_OK)DECODE_FAIL(result);
            if(operand.reg!=4 && operand.reg!=5 && operand.reg!=7)DECODE_FAIL(PW_ERR_UNSUPPORTED);
            length=1+operand.bytes+(op==0xc1);
            can_fault=(operand.mod!=3);
            /* A masked zero shift count preserves every flag.  Immediate
             * zero can be resolved now; CL is dynamic, so model it as both
             * defining and consuming the deterministic flag subset. */
            if(op==0xc1 && length<=bytes-cursor) {
                unsigned count=source[cursor+length-1]&31;
                flags_def=count==0?0:count==1?0x8c5:0x0c5;
            } else {
                flags_def=0x8c5;
                if(op==0xd3)flags_use=0x8c5;
            }
        } else if(op==0x69 || op==0x6b) {
            int result=decode_operand(source+cursor+1,bytes-cursor-1,&operand);
            if(result!=PW_OK)DECODE_FAIL(result);
            length=1+operand.bytes+(op==0x69?4:1);
            can_fault=(operand.mod!=3);
            flags_def=0x801;
        } else if(op<=0x3a && ((op&7)==0 || (op&7)==2)) {
            byte_alu=(op>>3)+1;byte_direction=!!(op&2);
            int result=decode_operand(source+cursor+1,bytes-cursor-1,&operand);
            if(result!=PW_OK)DECODE_FAIL(result);
            length=1+operand.bytes;
            can_fault=(operand.mod!=3);
            unsigned op_b=byte_alu-1;
            flags_def=(op_b==1||op_b==4||op_b==6)?0x8c5:0x8d5;
            if(op_b==2||op_b==3)flags_use=0x001;
        } else if(op==0x80 || op==0x88 || op==0x8a || op==0xc6 || op==0x38 || op==0x3a || op==0x84 || op==0xf6) {
            int result=decode_operand(source+cursor+1,bytes-cursor-1,&operand);
            if(result!=PW_OK)DECODE_FAIL(result);
            if((op==0xc6 || op==0xf6) && operand.reg!=0)DECODE_FAIL(PW_ERR_UNSUPPORTED);
            length=1+operand.bytes+(op==0x80 || op==0xc6 || op==0xf6);
            can_fault=(operand.mod!=3);
            if(op==0x80) {
                flags_def=(operand.reg==1||operand.reg==4||operand.reg==6)?0x8c5:0x8d5;
                if(operand.reg==2||operand.reg==3)flags_use=0x001;
            } else if(op==0x38||op==0x3a) flags_def=0x8d5;
            else if(op==0x84||op==0xf6) flags_def=0x8c5;
        } else if((op<=0x3c && (op&7)==4) || op==0xa8 || (op>=0xb0 && op<=0xb7)) {
            length=2;
            if(op==0xa8) flags_def=0x8c5;
            else if(op<=0x3c && (op&7)==4) {
                flags_def=(op==0x0c||op==0x24||op==0x34)?0x8c5:0x8d5;
                if((op>>3)==2||(op>>3)==3)flags_use=0x001;
            }
        } else if(op>=0x40 && op<=0x4f) {
            length=1; flags_def=0x8d4;
        } else if(op==0x85 || op==0xf7 || op==0xa9) {
            if(op==0xa9){memset(&operand,0,sizeof(operand));operand.mod=3;operand.rm=0;length=5;flags_def=0x8c5;}
            else {
                int result=decode_operand(source+cursor+1,bytes-cursor-1,&operand);
                if(result!=PW_OK)DECODE_FAIL(result);
                if(op==0xf7 && operand.reg!=0 && operand.reg<2)DECODE_FAIL(PW_ERR_UNSUPPORTED);
                length=1+operand.bytes+(op==0xf7 && operand.reg==0?4:0);
                can_fault=(operand.mod!=3);
                if(op==0x85) flags_def=0x8c5;
                else if(op==0xf7) {
                    if(operand.reg==0) flags_def=0x8c5;
                    else if(operand.reg==3) flags_def=0x8d5;
                }
            }
        } else if(op==0x66 || op==0x81 || op==0x83 || (op<=0x3d && (op&7)==5)) {
            size_t prefix=op==0x66?1:0;
            if(bytes-cursor<=prefix)DECODE_FAIL(PW_ERR_TRUNCATED);
            unsigned cmpop=source[cursor+prefix];
            unsigned accumulator=cmpop<=0x3d && (cmpop&7)==5;
            if(cmpop!=0x81 && cmpop!=0x83 && !accumulator)DECODE_FAIL(PW_ERR_UNSUPPORTED);
            word_operand=(unsigned)prefix;short_imm=cmpop==0x83;compare=1;
            if(accumulator) {memset(&operand,0,sizeof(operand));operand.mod=3;operand.rm=0;alu=cmpop>>3;}
            else {
                int result=decode_operand(source+cursor+prefix+1,bytes-cursor-prefix-1,&operand);
                if(result!=PW_OK)DECODE_FAIL(result);
                alu=operand.reg;
            }
            length=prefix+1+operand.bytes+(short_imm?1:word_operand?2:4);
            can_fault=(operand.mod!=3);
            flags_def=(alu==1||alu==4||alu==6)?0x8c5:0x8d5;
            if(alu==2||alu==3)flags_use=0x001;
        } else if(op>=0x70 && op<=0x7f) {
            conditional=1;length=2;terminal=1;
            flags_use=branch_condition_flags(op&0xf);
        } else if(op==0x0f) {
            if(bytes-cursor<2)DECODE_FAIL(PW_ERR_TRUNCATED);
            if(source[cursor+1]>=0x80 && source[cursor+1]<=0x8f){
                conditional=1;length=6;terminal=1;
                flags_use=branch_condition_flags(source[cursor+1]&0xf);
            }
            else if(source[cursor+1]==0xaf) {
                int result=decode_operand(source+cursor+2,bytes-cursor-2,&operand);
                if(result!=PW_OK)DECODE_FAIL(result);
                imul_general=1;length=2+operand.bytes;can_fault=(operand.mod!=3);flags_def=0x801;
            }
            else if(source[cursor+1]==0xb6 || source[cursor+1]==0xb7 || source[cursor+1]==0xbe || source[cursor+1]==0xbf || (source[cursor+1]>=0x90 && source[cursor+1]<=0x9f)) {
                int result=decode_operand(source+cursor+2,bytes-cursor-2,&operand);
                if(result!=PW_OK)DECODE_FAIL(result);
                extend=source[cursor+1]>=0xb6;setcc=!extend;
                if(setcc && operand.mod!=3)DECODE_FAIL(PW_ERR_UNSUPPORTED);
                length=2+operand.bytes;can_fault=(operand.mod!=3);
                if(setcc) flags_use=branch_condition_flags(source[cursor+1]&0xf);
            } else DECODE_FAIL(PW_ERR_UNSUPPORTED);
        } else if (op == 0x64) {
            if (bytes-cursor < 2) DECODE_FAIL(PW_ERR_TRUNCATED);
            if (source[cursor+1]!=0xa1 && source[cursor+1]!=0xa3)
                DECODE_FAIL(PW_ERR_UNSUPPORTED);
            length=6;can_fault=1;
        } else if (op == 0x89 || op == 0x8b || op == 0x8d || op==0xc7 ||
                   op==0x01 || op==0x03 || op==0x09 || op==0x0b ||
                   op==0x11 || op==0x13 || op==0x19 || op==0x1b ||
                   op==0x21 || op==0x23 || op==0x29 || op==0x2b ||
                   op==0x31 || op==0x33 || op==0xff || op==0x39 || op==0x3b) {
            int result=decode_operand(source+cursor+1,bytes-cursor-1,&operand);
            if (result!=PW_OK) DECODE_FAIL(result);
            if (op==0x8d && operand.mod==3) DECODE_FAIL(PW_ERR_UNSUPPORTED);
            if (op==0xc7 && operand.reg!=0) DECODE_FAIL(PW_ERR_UNSUPPORTED);
            if (op==0xff && operand.reg!=0 && operand.reg!=1 && operand.reg!=2 && operand.reg!=4 && operand.reg!=6) DECODE_FAIL(PW_ERR_UNSUPPORTED);
            length=1+operand.bytes;
            if (op==0xc7) length+=4;
            can_fault=(operand.mod!=3);
            if(op==0x8d) can_fault=0;
            else if(op==0x09||op==0x0b||op==0x21||op==0x23||op==0x31||op==0x33) flags_def=0x8c5;
            else if(op==0x01||op==0x03||op==0x29||op==0x2b||op==0x39||op==0x3b) flags_def=0x8d5;
            else if(op==0x11||op==0x13||op==0x19||op==0x1b) { flags_def=0x8d5; flags_use=0x001; }
            else if(op==0xff) {
                if(operand.reg==0||operand.reg==1) flags_def=0x8d4;
                else if(operand.reg==2||operand.reg==4) { terminal=1; can_fault=1; }
                else if(operand.reg==6) can_fault=1;
            }
        } else if (op == 0x6a) { length = 2; can_fault = 1; }
        else if (op == 0xeb) { length = 2; terminal = 1; }
        else if (op == 0x68) { length = 5; can_fault = 1; }
        else if (op == 0xe8) { length = 5; terminal = 1; can_fault = 1; }
        else if (op == 0xe9) { length = 5; terminal = 1; }
        else if (op == 0xa1 || op == 0xa3) { length = 5; can_fault = 1; }
        else if (op >= 0xb8 && op <= 0xbf) length = 5;
        else if (op == 0xc2) { length = 3; terminal = 1; can_fault = 1; }
        else if (op == 0xc3) { length = 1; terminal = 1; can_fault = 1; }
        else if (op == 0xc9) { length = 1; can_fault = 1; }
        else if (op == 0x99 || op == 0x90) length = 1;
        else if (op >= 0x50 && op <= 0x5f) { length = 1; can_fault = 1; }
        else DECODE_FAIL(PW_ERR_UNSUPPORTED);
        if (length > bytes-cursor) DECODE_FAIL(PW_ERR_TRUNCATED);

        d->length = length;
        d->operand = operand;
        d->compare = compare;
        d->alu = alu;
        d->short_imm = short_imm;
        d->word_operand = word_operand;
        d->conditional = conditional;
        d->extend = extend;
        d->setcc = setcc;
        d->extend_word_destination = extend_word_destination;
        d->x87 = x87;
        d->x87_width = x87_width;
        d->x87_write = x87_write;
        d->x87_register = x87_register;
        d->string_op = string_op;
        d->string_width = string_width;
        d->string_repeat = string_repeat;
        d->word_general = word_general;
        d->byte_alu = byte_alu;
        d->byte_direction = byte_direction;
        d->imul_general = imul_general;
        d->terminal = terminal;
        d->flags_def = flags_def;
        d->flags_use = flags_use;
        d->can_fault = can_fault;

        if (operand.mod == 3) {
            if (operand.rm < 8) gpr_uses[operand.rm]++;
        } else if (operand.bytes > 0) {
            if (operand.base >= 0 && operand.base < 8) gpr_uses[operand.base]++;
            if (operand.index >= 0 && operand.index < 8) gpr_uses[operand.index]++;
        }
        if (operand.reg < 8) gpr_uses[operand.reg]++;
        if (op >= 0x40 && op <= 0x4f) gpr_uses[op & 7]++;
        if (op >= 0x50 && op <= 0x57) { gpr_uses[op - 0x50]++; gpr_uses[4] += 2; }
        if (op >= 0x58 && op <= 0x5f) { gpr_uses[op - 0x58]++; gpr_uses[4] += 2; }
        if (op >= 0xb8 && op <= 0xbf) gpr_uses[op - 0xb8]++;
        if (op == 0x99) { gpr_uses[0]++; gpr_uses[2]++; }
        if (op == 0xc9) { gpr_uses[4] += 2; gpr_uses[5] += 2; }
        if (op == 0xa1 || op == 0xa3) gpr_uses[0]++;
        if (op == 0x6a || op == 0x68 || op == 0xe8) gpr_uses[4] += 2;
        if (op == 0xc3 || op == 0xc2) gpr_uses[4] += 2;
        if (op == 0xd3) gpr_uses[1]++;
        if (string_op) { gpr_uses[1]++; gpr_uses[6]++; gpr_uses[7]++; }
        if (x87 && (op == 0xd9 && operand.reg == 0x07)) gpr_uses[0]++;
        if (imul_general || (op == 0xf7 && operand.reg >= 4)) { gpr_uses[0]++; gpr_uses[2]++; }

        cursor += length;
        ++count;
        if (d->terminal) break;
    }

analyze_and_emit:
    if (!count) return PW_ERR_UNSUPPORTED;

    /* Backward liveness analysis across the basic block (FEX Dead Flag Elimination) */
    uint32_t live = 0x8d5; /* All arithmetic flags live at block exit */
    for (int i = (int)count - 1; i >= 0; i--) {
        if (insts[i].flags_def) {
            if ((insts[i].flags_def & live) == 0) {
                insts[i].flags_dead = 1;
            } else {
                insts[i].flags_dead = 0;
            }
            live = (live & ~insts[i].flags_def) | insts[i].flags_use;
        } else {
            live |= insts[i].flags_use;
        }
        /* Guards run before the guest instruction changes flags.  A fault
         * therefore observes every incoming arithmetic flag, so the barrier
         * applies to live-in (after the def/use transfer), not live-out. */
        if (insts[i].can_fault) live |= 0x8d5;
    }

    /* Allocate resident registers based on use frequencies */
    memset(&block->entry_contract, 0, sizeof(block->entry_contract));
    for (int i = 0; i < 8; i++) block->entry_contract.guest_to_host[i] = -1;
    for (int i = 0; i < PW_X86_MAX_HOST_REGS; i++) block->entry_contract.host_to_guest[i] = -1;

    if (residency_enabled) {
        for (int h = 0; h < PW_X86_MAX_HOST_REGS; h++) {
            int best_gpr = -1;
            unsigned max_uses = 0;
            for (int g = 0; g < 8; g++) {
                if (block->entry_contract.guest_to_host[g] == -1 && gpr_uses[g] > max_uses) {
                    max_uses = gpr_uses[g];
                    best_gpr = g;
                }
            }
            if (best_gpr >= 0) {
                block->entry_contract.resident_mask |= (1 << best_gpr);
                block->entry_contract.guest_to_host[best_gpr] = (int8_t)h;
                block->entry_contract.host_to_guest[h] = (int8_t)best_gpr;
            }
        }
    }
    block->exit_contract = block->entry_contract;
    /* A matching chain entry can inherit resident values that are newer than
     * canonical state.  The block has multiple possible predecessors, so a
     * static contract cannot know their per-register dirty masks.  Treat all
     * resident values as dirty until the first emitted spill barrier.  A
     * canonical entry may perform harmless redundant stores; a chain entry
     * must never lose a predecessor's update. */
    block->exit_contract.dirty_mask = block->entry_contract.resident_mask;

    /* Pass 2: Machine code emission */
    block->canonical_entry_offset = e.n;
    if (block->entry_contract.resident_mask) {
        emit_load_all_resident(&e, &block->entry_contract);
        uint8_t n_res = popcount8(block->entry_contract.resident_mask);
        byte(&e, 0x83); byte(&e, 0x47); byte(&e, offsetof(PwX86State, reg_loads)); byte(&e, n_res);
    }
    block->chain_entry_offset = e.n;


    for (unsigned i = 0; i < count; i++) {
        DecodedInst *d = &insts[i];
        size_t cursor = d->cursor;
        size_t length = d->length;
        uint8_t op = d->op;
        Operand operand = d->operand;
        unsigned compare = d->compare;
        unsigned alu = d->alu;
        unsigned short_imm = d->short_imm;
        unsigned word_operand = d->word_operand;
        unsigned conditional = d->conditional;
        unsigned extend = d->extend;
        unsigned setcc = d->setcc;
        unsigned extend_word_destination = d->extend_word_destination;
        unsigned x87 = d->x87;
        unsigned x87_width = d->x87_width;
        unsigned x87_write = d->x87_write;
        unsigned x87_register = d->x87_register;
        unsigned string_op = d->string_op;
        unsigned string_width = d->string_width;
        unsigned string_repeat = d->string_repeat;
        unsigned word_general = d->word_general;
        unsigned byte_alu = d->byte_alu;
        unsigned byte_direction = d->byte_direction;
        unsigned imul_general = d->imul_general;
        int terminal = d->terminal; (void)terminal;

        uint32_t next = pc + (uint32_t)cursor + (uint32_t)length;
        /* Fault exits preserve the PC of the faulting guest instruction. */
        store(&e,offsetof(PwX86State,eip),pc+(uint32_t)cursor);
        if (d->can_fault || string_op || x87) {
            emit_spill_dirty(&e, &block->exit_contract);
            block->exit_contract.dirty_mask = 0;
        }
        if(string_op) {
            /* The helper can consume and replace arithmetic EFLAGS (CMPS/REP),
             * so it is a descriptor ownership boundary. */
            emit_commit_flags(&e);
            string_call(&e,string_op,string_width,string_repeat);
            emit_load_all_resident(&e, &block->exit_contract);
        }
        else if(byte_alu) {
            unsigned operation=byte_alu-1;
            unsigned rm=(operand.rm&3)*4+(operand.rm>>2);
            unsigned reg=(operand.reg&3)*4+(operand.reg>>2);
            /* Materialization calls C and may clobber operand temporaries.  Do it
             * before loading either byte operand, then import CF immediately
             * before the native ADC/SBB instruction. */
            if(operation==2 || operation==3)
                emit_materialize_flags(&e,0x001);
            if(operand.mod!=3) {
                effective_address(&e,&operand,&block->exit_contract);
                memory_address_width(&e,!byte_direction && operation!=7?2:0,1);
            }
            if(byte_direction) {
                if(operand.mod==3) {
                    byte(&e,0x0f);byte(&e,0xb6);byte(&e,0x4f);byte(&e,rm);
                } else {
                    byte(&e,0x0f);byte(&e,0xb6);byte(&e,0x00);
                    byte(&e,0x89);byte(&e,0xc1);
                }
                byte(&e,0x0f);byte(&e,0xb6);byte(&e,0x47);byte(&e,reg);
            } else if(operand.mod==3) {
                byte(&e,0x0f);byte(&e,0xb6);byte(&e,0x47);byte(&e,rm);
                byte(&e,0x0f);byte(&e,0xb6);byte(&e,0x4f);byte(&e,reg);
            } else {
                byte(&e,0x49);byte(&e,0x89);byte(&e,0xc0);
                byte(&e,0x41);byte(&e,0x0f);byte(&e,0xb6);byte(&e,0x00);
            }
            if(operation==2 || operation==3) {
                byte(&e,0x0f);byte(&e,0xba);byte(&e,0x67);
                byte(&e,offsetof(PwX86State,eflags));byte(&e,0);
            }
            if(!byte_direction && operand.mod!=3) {
                byte(&e,(uint8_t)(operation*8+2));byte(&e,0x47);byte(&e,reg);
                if(operation!=7){byte(&e,0x41);byte(&e,0x88);byte(&e,0x00);}
            } else {
                byte(&e,(uint8_t)(operation*8));byte(&e,0xc8);
                if(operation!=7) {
                    unsigned destination=byte_direction?reg:rm;
                    byte(&e,0x88);byte(&e,0x47);byte(&e,destination);
                    unsigned gpr = destination / 4;
                    if (get_resident_host_reg(&block->exit_contract, gpr) >= 0) {
                        emit_load_single(&e, &block->exit_contract, gpr);
                        block->exit_contract.dirty_mask |= (1 << gpr);
                    }
                }
            }
            emit_save_flags(&e, (operation==1 || operation==4 || operation==6)?0x8c5:0x8d5,
                            lazy_flags_enabled, d->flags_dead);
        }
        else if(imul_general) {
            if(operand.mod==3)load_guest_reg(&e, &block->exit_contract, operand.rm);
            else {effective_address(&e,&operand,&block->exit_contract);memory_address_width(&e,0,4);byte(&e,0x8b);byte(&e,0x00);}
            int h_reg = get_resident_host_reg(&block->exit_contract, operand.reg);
            if (h_reg >= 0) {
                byte(&e, 0x41); byte(&e, 0x0f); byte(&e, 0xaf); byte(&e, (uint8_t)(0xc0 | h_reg));
            } else {
                byte(&e,0x0f);byte(&e,0xaf);byte(&e,0x47);byte(&e,operand.reg*4);
            }
            store_guest_reg(&e, &block->exit_contract, operand.reg);
            emit_save_flags(&e, 0x801, lazy_flags_enabled, d->flags_dead);
        }
        else if(op==0x69 || op==0x6b) {
            if(operand.mod==3)load_guest_reg(&e, &block->exit_contract, operand.rm);
            else {effective_address(&e,&operand,&block->exit_contract);memory_address_width(&e,0,4);byte(&e,0x8b);byte(&e,0x00);}
            byte(&e,op);byte(&e,0xc0);
            if(op==0x69)word(&e,read32(source+cursor+length-4));
            else byte(&e,source[cursor+length-1]);
            store_guest_reg(&e, &block->exit_contract, operand.reg);
            emit_save_flags(&e, 0x801, lazy_flags_enabled, d->flags_dead);
        }
        else if(word_general) {
            unsigned load=word_general==0x8b;
            unsigned alu_word=word_general<=0x33 &&
                ((word_general&7)==1 || (word_general&7)==3);
            unsigned compare_word=word_general==0x39 || word_general==0x3b;
            unsigned test_word=word_general==0x85;
            unsigned immediate_word=word_general==0xc7;
            if(immediate_word) {
                uint16_t value=(uint16_t)source[cursor+length-2]|
                    (uint16_t)source[cursor+length-1]<<8;
                if(operand.mod==3) {
                    emit_spill_single(&e, &block->exit_contract, operand.rm);
                    byte(&e,0x66);byte(&e,0xc7);byte(&e,0x47);byte(&e,operand.rm*4);
                    byte(&e,(uint8_t)value);byte(&e,(uint8_t)(value>>8));
                    if (get_resident_host_reg(&block->exit_contract, operand.rm) >= 0) {
                        emit_load_single(&e, &block->exit_contract, operand.rm);
                        block->exit_contract.dirty_mask |= (1 << operand.rm);
                    }
                } else {
                    effective_address(&e,&operand,&block->exit_contract);memory_address_width(&e,1,2);
                    byte(&e,0x66);byte(&e,0xc7);byte(&e,0x00);
                    byte(&e,(uint8_t)value);byte(&e,(uint8_t)(value>>8));
                }
            } else if(alu_word) {
                unsigned memory_destination=(word_general&7)==1;
                unsigned operation=word_general>>3;
                unsigned logical=operation==1 || operation==4 || operation==6;
                if(operation==2 || operation==3)
                    emit_materialize_flags(&e,0x001);
                if(operand.mod==3) {
                    unsigned destination=memory_destination?operand.rm:operand.reg;
                    unsigned source_register=memory_destination?operand.reg:operand.rm;
                    emit_spill_single(&e, &block->exit_contract, destination);
                    emit_spill_single(&e, &block->exit_contract, source_register);
                    load_guest_reg(&e,&block->exit_contract,destination);byte(&e,0x66);
                    if(operation==2 || operation==3) {
                        byte(&e,0x0f);byte(&e,0xba);byte(&e,0x67);
                        byte(&e,offsetof(PwX86State,eflags));byte(&e,0);
                    }
                    byte(&e,(uint8_t)(operation*8+3));byte(&e,0x47);
                    byte(&e,source_register*4);
                    byte(&e,0x66);byte(&e,0x89);byte(&e,0x47);byte(&e,destination*4);
                    if (get_resident_host_reg(&block->exit_contract, destination) >= 0) {
                        emit_load_single(&e, &block->exit_contract, destination);
                        block->exit_contract.dirty_mask |= (1 << destination);
                    }
                } else {
                    effective_address(&e,&operand,&block->exit_contract);memory_address_width(&e,memory_destination,2);
                    if(memory_destination) {
                        byte(&e,0x8b);byte(&e,0x4f);byte(&e,operand.reg*4);
                        if(operation==2 || operation==3) {
                            byte(&e,0x0f);byte(&e,0xba);byte(&e,0x67);
                            byte(&e,offsetof(PwX86State,eflags));byte(&e,0);
                        }
                        byte(&e,0x66);byte(&e,word_general);byte(&e,0x08);
                    } else {
                        byte(&e,0x0f);byte(&e,0xb7);byte(&e,0x08);
                        load_guest_reg(&e,&block->exit_contract,operand.reg);byte(&e,0x66);
                        if(operation==2 || operation==3) {
                            byte(&e,0x0f);byte(&e,0xba);byte(&e,0x67);
                            byte(&e,offsetof(PwX86State,eflags));byte(&e,0);
                        }
                        byte(&e,word_general);byte(&e,0xc8);
                        byte(&e,0x66);byte(&e,0x89);byte(&e,0x47);byte(&e,operand.reg*4);
                        if (get_resident_host_reg(&block->exit_contract, operand.reg) >= 0) {
                            emit_load_single(&e, &block->exit_contract, operand.reg);
                            block->exit_contract.dirty_mask |= (1 << operand.reg);
                        }
                    }
                }
                emit_save_flags(&e, logical?0x8c5:0x8d5, lazy_flags_enabled, d->flags_dead);
            } else if(operand.mod==3) {
                emit_spill_single(&e, &block->exit_contract, operand.rm);
                emit_spill_single(&e, &block->exit_contract, operand.reg);
                if(word_general==0x89) {
                    load_guest_reg(&e,&block->exit_contract,operand.reg);byte(&e,0x66);byte(&e,0x89);
                    byte(&e,0x47);byte(&e,operand.rm*4);
                    if (get_resident_host_reg(&block->exit_contract, operand.rm) >= 0) {
                        emit_load_single(&e, &block->exit_contract, operand.rm);
                        block->exit_contract.dirty_mask |= (1 << operand.rm);
                    }
                } else if(word_general==0x8b) {
                    load_guest_reg(&e,&block->exit_contract,operand.rm);byte(&e,0x66);byte(&e,0x89);
                    byte(&e,0x47);byte(&e,operand.reg*4);
                    if (get_resident_host_reg(&block->exit_contract, operand.reg) >= 0) {
                        emit_load_single(&e, &block->exit_contract, operand.reg);
                        block->exit_contract.dirty_mask |= (1 << operand.reg);
                    }
                } else if(compare_word) {
                    load_guest_reg(&e,&block->exit_contract,(word_general==0x39?operand.rm:operand.reg));
                    byte(&e,0x66);byte(&e,0x3b);byte(&e,0x47);
                    byte(&e,(word_general==0x39?operand.reg:operand.rm)*4);
                } else {
                    load_guest_reg(&e,&block->exit_contract,operand.rm);byte(&e,0x66);byte(&e,0x85);
                    byte(&e,0x47);byte(&e,operand.reg*4);
                }
            } else {
                effective_address(&e,&operand,&block->exit_contract);
                memory_address_width(&e,!load && !compare_word && !test_word,2);
                if(word_general==0x89) {
                    byte(&e,0x8b);byte(&e,0x4f);byte(&e,operand.reg*4);
                    byte(&e,0x66);byte(&e,word_general);byte(&e,0x08);
                } else if(word_general==0x8b) {
                    byte(&e,0x0f);byte(&e,0xb7);byte(&e,0x00);
                    byte(&e,0x66);byte(&e,0x89);byte(&e,0x47);byte(&e,operand.reg*4);
                    if (get_resident_host_reg(&block->exit_contract, operand.reg) >= 0) {
                        emit_load_single(&e, &block->exit_contract, operand.reg);
                        block->exit_contract.dirty_mask |= (1 << operand.reg);
                    }
                } else if(word_general==0x39) {
                    byte(&e,0x66);byte(&e,0x8b);byte(&e,0x00);
                    byte(&e,0x66);byte(&e,0x3b);byte(&e,0x47);byte(&e,operand.reg*4);
                } else if(compare_word) {
                    byte(&e,0x0f);byte(&e,0xb7);byte(&e,0x08);
                    load_guest_reg(&e,&block->exit_contract,operand.reg);byte(&e,0x66);byte(&e,0x39);byte(&e,0xc8);
                } else {
                    byte(&e,0x66);byte(&e,0x8b);byte(&e,0x00);
                    byte(&e,0x66);byte(&e,0x85);byte(&e,0x47);byte(&e,operand.reg*4);
                }
            }
            if(compare_word || test_word) emit_save_flags(&e, test_word?0x8c5:0x8d5, lazy_flags_enabled, d->flags_dead);
        }
        else if(x87) {
            if(operand.mod!=3){effective_address(&e,&operand,&block->exit_contract);memory_address_width(&e,x87_write,x87_width);}
            emit_spill_dirty(&e, &block->exit_contract);
            block->exit_contract.dirty_mask = 0;
            x87_call(&e,x87-1,x87_register);
            emit_load_all_resident(&e, &block->exit_contract);
        } else if(op==0xc1 || op==0xd1 || op==0xd3) {
            /* A zero-count shift preserves all arithmetic flags and wider
             * counts retain implementation-policy bits. Canonicalize the
             * previous producer before this eager variable-mask path. */
            emit_commit_flags(&e);
            if(operand.mod==3)load_guest_reg(&e, &block->exit_contract, operand.rm);
            else {effective_address(&e,&operand,&block->exit_contract);memory_address_width(&e,2,4);}
            if(op==0xd3){load_guest_reg_ecx(&e, &block->exit_contract, 1);}
            else {byte(&e,0xb9);word(&e,op==0xd1?1:source[cursor+length-1]);}
            byte(&e,0x83);byte(&e,0xe1);byte(&e,31); /* masked count */
            /* esi selects only defined flags: none for zero, OF only for one.
             * Preserve undefined AF and multi-bit OF deterministically. */
            byte(&e,0xbe);word(&e,0xc5);
            byte(&e,0xba);word(&e,0);
            byte(&e,0x85);byte(&e,0xc9);
            byte(&e,0x0f);byte(&e,0x44);byte(&e,0xf2);
            byte(&e,0xba);word(&e,0x8c5);
            byte(&e,0x83);byte(&e,0xf9);byte(&e,1);
            byte(&e,0x0f);byte(&e,0x44);byte(&e,0xf2);
            byte(&e,0xd3);byte(&e,(operand.mod==3?0xc0:0)|(operand.reg<<3));
            if(operand.mod==3)store_guest_reg(&e, &block->exit_contract, operand.rm);
            if (!d->flags_dead) {
                byte(&e,0x9c);byte(&e,0x5a); /* snapshot native flags */
                byte(&e,0x21);byte(&e,0xf2); /* and edx, esi */
                byte(&e,0xf7);byte(&e,0xd6); /* not esi */
                byte(&e,0x23);byte(&e,0x77);byte(&e,offsetof(PwX86State,eflags)); /* and esi, [rdi+eflags] */
                byte(&e,0x09);byte(&e,0xf2); /* or edx, esi */
                byte(&e,0x89);byte(&e,0x57);byte(&e,offsetof(PwX86State,eflags));
            }
        } else if(op>=0x40 && op<=0x4f) {
            unsigned reg=op&7;load_guest_reg(&e, &block->exit_contract, reg);
            byte(&e,0xff);byte(&e,op<0x48?0xc0:0xc8);store_guest_reg(&e, &block->exit_contract, reg);
            emit_save_flags(&e, 0x8d4, lazy_flags_enabled, d->flags_dead); /* INC/DEC preserve guest CF. */
        } else if(op>=0xb0 && op<=0xb7) {
            unsigned reg=op&7;
            emit_spill_single(&e, &block->exit_contract, reg & 3);
            byte(&e,0xc6);byte(&e,0x47);byte(&e,(reg&3)*4+(reg>>2));byte(&e,source[cursor+1]);
            if (get_resident_host_reg(&block->exit_contract, reg & 3) >= 0) {
                emit_load_single(&e, &block->exit_contract, reg & 3);
                block->exit_contract.dirty_mask |= (1 << (reg & 3));
            }
        } else if((op<=0x3c && (op&7)==4) || op==0xa8) {
            unsigned operation=op>>3;
            if(op!=0xa8 && (operation==2 || operation==3))
                emit_materialize_flags(&e,0x001);
            load_guest_reg(&e, &block->exit_contract, 0);
            if(op!=0xa8 && (operation==2 || operation==3)) {
                /* Reload native CF after operand setup and before ADC/SBB AL. */
                byte(&e,0x0f);byte(&e,0xba);byte(&e,0x67);
                byte(&e,offsetof(PwX86State,eflags));byte(&e,0);
            }
            byte(&e,op);byte(&e,source[cursor+1]);
            if(op!=0x3c && op!=0xa8)store_guest_reg(&e, &block->exit_contract, 0);
            emit_save_flags(&e, (op==0x0c || op==0x24 || op==0x34 || op==0xa8)?0x8c5:0x8d5,
                            lazy_flags_enabled, d->flags_dead);
        } else if(op==0x80 || op==0x88 || op==0x8a || op==0xc6 || op==0x38 || op==0x3a || op==0x84 || op==0xf6) {
            unsigned dest=(operand.rm&3)*4+(operand.rm>>2),reg=(operand.reg&3)*4+(operand.reg>>2);
            unsigned immediate_alu=op==0x80;
            unsigned write=op==0x88 || op==0xc6 || (immediate_alu && operand.reg!=7);
            if(immediate_alu && (operand.reg==2 || operand.reg==3))
                emit_materialize_flags(&e,0x001);
            if(operand.mod!=3){effective_address(&e,&operand,&block->exit_contract);memory_address_width(&e,write,1);}
            else emit_spill_single(&e, &block->exit_contract, operand.rm & 3);
            emit_spill_single(&e, &block->exit_contract, operand.reg & 3);
            if(immediate_alu) {
                    if(operand.reg==2 || operand.reg==3) {
                        byte(&e,0x0f);byte(&e,0xba);byte(&e,0x67);
                        byte(&e,offsetof(PwX86State,eflags));byte(&e,0);
                    }
                    byte(&e,0x80);byte(&e,operand.mod==3?
                        (uint8_t)(0x47|(operand.reg<<3)):(uint8_t)(operand.reg<<3));
                    if(operand.mod==3)byte(&e,dest);
                    byte(&e,source[cursor+length-1]);
                    if(operand.mod==3 && operand.reg!=7) {
                        if (get_resident_host_reg(&block->exit_contract, operand.rm & 3) >= 0) {
                            emit_load_single(&e, &block->exit_contract, operand.rm & 3);
                            block->exit_contract.dirty_mask |= (1 << (operand.rm & 3));
                        }
                    }
                    emit_save_flags(&e, (operand.reg==1 || operand.reg==4 || operand.reg==6)?0x8c5:0x8d5,
                                    lazy_flags_enabled, d->flags_dead);
            } else if(write) {
                if(op==0xc6) {
                    byte(&e,0xc6);byte(&e,operand.mod==3?0x47:0x00);
                    if(operand.mod==3)byte(&e,dest);
                    byte(&e,source[cursor+length-1]);
                    if(operand.mod==3) {
                        if (get_resident_host_reg(&block->exit_contract, operand.rm & 3) >= 0) {
                            emit_load_single(&e, &block->exit_contract, operand.rm & 3);
                            block->exit_contract.dirty_mask |= (1 << (operand.rm & 3));
                        }
                    }
                } else {
                    byte(&e,0x0f);byte(&e,0xb6);byte(&e,0x4f);byte(&e,reg);
                    byte(&e,0x88);byte(&e,operand.mod==3?0x4f:0x08);
                    if(operand.mod==3)byte(&e,dest);
                    if(operand.mod==3) {
                        if (get_resident_host_reg(&block->exit_contract, operand.rm & 3) >= 0) {
                            emit_load_single(&e, &block->exit_contract, operand.rm & 3);
                            block->exit_contract.dirty_mask |= (1 << (operand.rm & 3));
                        }
                    }
                }
            } else {
                byte(&e,0x0f);byte(&e,0xb6);byte(&e,operand.mod==3?0x47:0x00);
                if(operand.mod==3)byte(&e,dest);
                if(op==0x8a){
                    byte(&e,0x88);byte(&e,0x47);byte(&e,reg);
                    if (get_resident_host_reg(&block->exit_contract, operand.reg & 3) >= 0) {
                        emit_load_single(&e, &block->exit_contract, operand.reg & 3);
                        block->exit_contract.dirty_mask |= (1 << (operand.reg & 3));
                    }
                }
                else {
                    if(op==0xf6){byte(&e,0xa8);byte(&e,source[cursor+length-1]);}
                    else if(op==0x3a) {
                        byte(&e,0x89);byte(&e,0xc1);
                        byte(&e,0x0f);byte(&e,0xb6);byte(&e,0x47);byte(&e,reg);
                        byte(&e,0x38);byte(&e,0xc8);
                    } else {byte(&e,op==0x84?0x84:0x3a);byte(&e,0x47);byte(&e,reg);}
                    emit_save_flags(&e, (op==0x84 || op==0xf6)?0x8c5:0x8d5,
                                    lazy_flags_enabled, d->flags_dead);
                }
            }
        } else if(op==0x99) {
            load_guest_reg(&e, &block->exit_contract, 0);
            byte(&e,0x99); /* CDQ: sign-extend native EAX into native EDX. */
            store_guest_reg_edx(&e, &block->exit_contract, 2);
        } else if(op==0xc9) {
            load_guest_reg(&e, &block->exit_contract, 5);stack_bounds(&e);
            byte(&e,0x8b);byte(&e,0x08);
            byte(&e,0x83);byte(&e,0xc0);byte(&e,4);
            store_guest_reg(&e, &block->exit_contract, 4);
            byte(&e,0x89);byte(&e,0x4f);byte(&e,offsetof(PwX86State,gpr[5]));
            if (get_resident_host_reg(&block->exit_contract, 5) >= 0) {
                emit_load_single(&e, &block->exit_contract, 5);
                block->exit_contract.dirty_mask |= (1 << 5);
            }
        } else if(op==0xf7 && operand.reg>=4) {
            if(operand.mod==3)load_guest_reg(&e, &block->exit_contract, operand.rm);
            else {effective_address(&e,&operand,&block->exit_contract);memory_address_width(&e,0,4);byte(&e,0x8b);byte(&e,0x00);}
            emit_spill_dirty(&e, &block->exit_contract);
            block->exit_contract.dirty_mask = 0;
            muldiv_call(&e,operand.reg);
            emit_load_all_resident(&e, &block->exit_contract);
        } else if(op==0xf7 && operand.reg!=0) {
            if(operand.mod==3)load_guest_reg(&e, &block->exit_contract, operand.rm);
            else {effective_address(&e,&operand,&block->exit_contract);memory_address_width(&e,2,4);}
            byte(&e,0xf7);byte(&e,(operand.mod==3?0xc0:0)|(operand.reg<<3));
            if(operand.mod==3)store_guest_reg(&e, &block->exit_contract, operand.rm);
            if(operand.reg==3) emit_save_flags(&e, 0x8d5, lazy_flags_enabled, d->flags_dead);
        } else if(op==0x85 || op==0xf7 || op==0xa9) {
            if(operand.mod==3)load_guest_reg(&e, &block->exit_contract, operand.rm);
            else {effective_address(&e,&operand,&block->exit_contract);memory_address(&e,0);byte(&e,0x8b);byte(&e,0x00);}
            if(op==0x85){
                int h = get_resident_host_reg(&block->exit_contract, operand.reg);
                if (h >= 0) {
                    byte(&e,0x44);byte(&e,0x85);byte(&e,(uint8_t)(0xc0 | (h << 3)));
                } else {
                    byte(&e,0x85);byte(&e,0x47);byte(&e,operand.reg*4);
                }
            }
            else {byte(&e,0xa9);word(&e,read32(source+cursor+length-4));}
            emit_save_flags(&e, 0x8c5, lazy_flags_enabled, d->flags_dead); /* TEST leaves AF undefined; retain it. */
        } else if(setcc) {
            emit_materialize_flags(&e,branch_condition_flags(source[cursor+1]&15));
            condition_value(&e,source[cursor+1]&15);
            unsigned reg=operand.rm&3,high=operand.rm>=4;
            if(high){byte(&e,0xc1);byte(&e,0xe0);byte(&e,8);}
            byte(&e,0x8b);byte(&e,0x57);byte(&e,reg*4);
            byte(&e,0x81);byte(&e,0xe2);word(&e,high?0xffff00ff:0xffffff00);
            byte(&e,0x09);byte(&e,0xc2);
            byte(&e,0x89);byte(&e,0x57);byte(&e,reg*4);
            if (get_resident_host_reg(&block->exit_contract, reg) >= 0) {
                emit_load_single(&e, &block->exit_contract, reg);
                block->exit_contract.dirty_mask |= (1 << reg);
            }
        } else if(op==0x39 || op==0x3b) {
            if(operand.mod==3)load_guest_reg(&e, &block->exit_contract, operand.rm);
            else {effective_address(&e,&operand,&block->exit_contract);memory_address(&e,0);byte(&e,0x8b);byte(&e,0x00);}
            if(op==0x39){
                int h = get_resident_host_reg(&block->exit_contract, operand.reg);
                if (h >= 0) {
                    byte(&e,0x44);byte(&e,0x39);byte(&e,(uint8_t)(0xc0 | (h << 3)));
                } else {
                    byte(&e,0x3b);byte(&e,0x47);byte(&e,operand.reg*4);
                }
            }
            else {
                byte(&e,0x89);byte(&e,0xc1);load_guest_reg(&e, &block->exit_contract, operand.reg);
                byte(&e,0x39);byte(&e,0xc8);
            }
            emit_save_flags(&e, 0x8d5, lazy_flags_enabled, d->flags_dead);
        } else if(extend) {
            unsigned opcode=source[cursor+(extend_word_destination?2:1)],width=(opcode&1)?2:1;
            if(operand.mod!=3){effective_address(&e,&operand,&block->exit_contract);memory_address_width(&e,0,width);}
            else emit_spill_single(&e, &block->exit_contract, width==1?(operand.rm&3):operand.rm);
            byte(&e,0x0f);byte(&e,opcode);byte(&e,operand.mod==3?0x47:0x00);
            if(operand.mod==3)byte(&e,width==1?(operand.rm&3)*4+(operand.rm>>2):operand.rm*4);
            if(extend_word_destination) {
                emit_spill_single(&e, &block->exit_contract, operand.reg);
                byte(&e,0x66);byte(&e,0x89);byte(&e,0x47);byte(&e,operand.reg*4);
                if (get_resident_host_reg(&block->exit_contract, operand.reg) >= 0) {
                    emit_load_single(&e, &block->exit_contract, operand.reg);
                    block->exit_contract.dirty_mask |= (1 << operand.reg);
                }
            } else store_guest_reg(&e, &block->exit_contract, operand.reg);
        } else if(compare) {
            /* A helper call cannot run after EAX contains the destination or
             * effective address.  Resolve pending guest CF first. */
            if(alu==2 || alu==3)
                emit_materialize_flags(&e,0x001);
            if(operand.mod==3)load_guest_reg(&e, &block->exit_contract, operand.rm);
            else {
                effective_address(&e,&operand,&block->exit_contract);memory_address_width(&e,alu!=7?2:0,word_operand?2:4);
            }
            {
                const uint8_t *imm=source+cursor+length-(short_imm?1:word_operand?2:4);
                uint32_t value=short_imm?(uint32_t)(int32_t)(int8_t)*imm:
                    word_operand?(uint32_t)imm[0]|(uint32_t)imm[1]<<8:read32(imm);
                /* Import only guest CF for ADC/SBB, never guest control flags. */
                if(alu==2 || alu==3) {
                    byte(&e,0x0f);byte(&e,0xba);byte(&e,0x67);
                    byte(&e,offsetof(PwX86State,eflags));byte(&e,0);
                }
                if(word_operand)byte(&e,0x66);
                if(operand.mod==3)byte(&e,(uint8_t)(5+alu*8));
                else {byte(&e,0x81);byte(&e,(uint8_t)(alu*8));}
                if(word_operand){byte(&e,(uint8_t)value);byte(&e,(uint8_t)(value>>8));}else word(&e,value);
                if(operand.mod==3 && alu!=7) {
                    if(word_operand) {
                        byte(&e,0x66);
                        byte(&e,0x89);byte(&e,0x47);byte(&e,operand.rm*4);
                        if (get_resident_host_reg(&block->exit_contract, operand.rm) >= 0) {
                            emit_load_single(&e, &block->exit_contract, operand.rm);
                            block->exit_contract.dirty_mask |= (1 << operand.rm);
                        }
                    } else {
                        store_guest_reg(&e, &block->exit_contract, operand.rm);
                    }
                }
                emit_save_flags(&e, (alu==1 || alu==4 || alu==6)?0x8c5:0x8d5,
                                lazy_flags_enabled, d->flags_dead);
            }
        } else if(conditional) {
            unsigned condition=(op==0x0f?source[cursor+1]:op)&15;
            uint32_t delta=op==0x0f?read32(source+cursor+2):(uint32_t)(int32_t)(int8_t)source[cursor+1];
            block->exit.kind = PW_X86_EXIT_CONDITIONAL;
            block->exit.chainable = 1;
            block->exit.target_pc = next + delta;
            block->exit.fallthrough_pc = next;
            conditional_target(&e,condition,next,next+delta,block,count);terminal=1;
        } else if(op==0xff && operand.reg<2) {
            if(operand.mod==3)load_guest_reg(&e, &block->exit_contract, operand.rm);
            else {effective_address(&e,&operand,&block->exit_contract);memory_address_width(&e,2,4);}
            byte(&e,0xff);byte(&e,(operand.mod==3?0xc0:0)|(operand.reg<<3));
            if(operand.mod==3)store_guest_reg(&e, &block->exit_contract, operand.rm);
            emit_save_flags(&e, 0x8d4, lazy_flags_enabled, d->flags_dead);
            store(&e,offsetof(PwX86State,eip),next);
        } else if (op==0xff) {
            if(operand.mod==3)load_guest_reg(&e, &block->exit_contract, operand.rm);
            else {
                effective_address(&e,&operand,&block->exit_contract);memory_address(&e,0);
                byte(&e,0x8b);byte(&e,0x00);
            }
            byte(&e,0x89);byte(&e,0xc1); /* preserve target across guest push */
            if (operand.reg==2) { /* near indirect call: push next guest PC */
                push_imm(&e,next,&block->exit_contract);
                byte(&e,0x89); byte(&e,0x4f); byte(&e,offsetof(PwX86State,eip));
            } else if (operand.reg==4) { /* near indirect jump */
                byte(&e,0x89); byte(&e,0x4f); byte(&e,offsetof(PwX86State,eip));
            } else { /* FF /6 push r/m32 */
                stack_address(&e,1,&block->exit_contract);
                byte(&e,0x89); byte(&e,0x08);
                store_guest_reg(&e, &block->exit_contract, 4);
                store(&e,offsetof(PwX86State,eip),next);
            }
            if (operand.reg==2 || operand.reg==4) terminal=1;
        } else if (op<=0x33 && ((op&7)==1 || (op&7)==3)) {
            unsigned reverse=(op&7)==1;
            unsigned operation=op>>3;
            unsigned logical=operation==1 || operation==4 || operation==6;
            unsigned dest=reverse?operand.rm:operand.reg;
            unsigned src=reverse?operand.reg:operand.rm;
            if(operation==2 || operation==3)
                emit_materialize_flags(&e,0x001);
            if(operand.mod==3) {
                if(operation==6 && dest==src) {
                    /* Strength reduction: xor reg, reg clears register without memory load */
                    byte(&e,0x31);byte(&e,0xc0); /* xor eax, eax */
                    store_guest_reg(&e, &block->exit_contract, dest);
                } else {
                    load_guest_reg(&e, &block->exit_contract, dest);
                    if(operation==2 || operation==3) {
                        byte(&e,0x0f);byte(&e,0xba);byte(&e,0x67);
                        byte(&e,offsetof(PwX86State,eflags));byte(&e,0);
                    }
                    int h_src = get_resident_host_reg(&block->exit_contract, src);
                    if (h_src >= 0) {
                        byte(&e,0x41);byte(&e,(uint8_t)(operation*8+3));byte(&e,(uint8_t)(0xc0 | h_src));
                    } else {
                        byte(&e,(uint8_t)(operation*8+3));byte(&e,0x47);byte(&e,src*4);
                    }
                    store_guest_reg(&e, &block->exit_contract, dest);
                }
            } else {
                effective_address(&e,&operand,&block->exit_contract);memory_address_width(&e,reverse?2:0,4);
                if(reverse) {
                    load_guest_reg_ecx(&e, &block->exit_contract, operand.reg);
                    if(operation==2 || operation==3) {
                        byte(&e,0x0f);byte(&e,0xba);byte(&e,0x67);
                        byte(&e,offsetof(PwX86State,eflags));byte(&e,0);
                    }
                    byte(&e,op);byte(&e,0x08); /* [rax] op ecx */
                } else {
                    byte(&e,0x8b);byte(&e,0x08); /* read memory before changing its address register */
                    load_guest_reg(&e, &block->exit_contract, operand.reg);
                    if(operation==2 || operation==3) {
                        byte(&e,0x0f);byte(&e,0xba);byte(&e,0x67);
                        byte(&e,offsetof(PwX86State,eflags));byte(&e,0);
                    }
                    byte(&e,(uint8_t)(operation*8+3));byte(&e,0xc1);
                    store_guest_reg(&e, &block->exit_contract, operand.reg);
                }
            }
            /* Logical AF is undefined: retain guest AF deterministically. */
            emit_save_flags(&e, logical?0x8c5:0x8d5, lazy_flags_enabled, d->flags_dead);
        } else if (op==0xc7) {
            uint32_t value=read32(source+cursor+length-4);
            if (operand.mod==3) store_guest_imm(&e, &block->exit_contract, operand.rm, value);
            else {
                effective_address(&e,&operand,&block->exit_contract);memory_address(&e,1);
                byte(&e,0xc7);byte(&e,0x00);word(&e,value);
            }
        } else if (op == 0x64 || op==0xa1 || op==0xa3) {
            unsigned load=op==0xa1 || (op==0x64 && source[cursor+1]==0xa1);
            if(op==0x64)fs_address(&e,read32(source+cursor+2));
            else {byte(&e,0xb8);word(&e,read32(source+cursor+1));memory_address(&e,!load);}
            if (load) {
                byte(&e,0x8b); byte(&e,0x00);
                store_guest_reg(&e, &block->exit_contract, 0);
            } else {
                load_guest_reg_ecx(&e, &block->exit_contract, 0);
                byte(&e,0x89); byte(&e,0x08);
            }
        } else if (op == 0x89 || op == 0x8b || op == 0x8d) {
            if (operand.mod==3) {
                if (operand.reg != operand.rm) {
                    load_guest_reg(&e, &block->exit_contract, (op==0x89 ? operand.reg:operand.rm));
                    store_guest_reg(&e, &block->exit_contract, (op==0x89 ? operand.rm:operand.reg));
                }
            } else {
                effective_address(&e,&operand,&block->exit_contract);
                if (op==0x8d) store_guest_reg(&e, &block->exit_contract, operand.reg);
                else {
                    memory_address(&e,op==0x89);
                    if (op==0x8b) {
                        byte(&e,0x8b); byte(&e,0x00);
                        store_guest_reg(&e, &block->exit_contract, operand.reg);
                    } else {
                        load_guest_reg_ecx(&e, &block->exit_contract, operand.reg);
                        byte(&e,0x89); byte(&e,0x08);
                    }
                }
            }
        } else if (op == 0x6a) push_imm(&e,(uint32_t)(int32_t)(int8_t)source[cursor+1], &block->exit_contract);
        else if (op == 0x68) push_imm(&e,read32(source+cursor+1), &block->exit_contract);
        else if (op >= 0x50 && op <= 0x57) {
            stack_address(&e,1,&block->exit_contract);
            load_guest_reg_ecx(&e, &block->exit_contract, op-0x50);
            byte(&e,0x89); byte(&e,0x08); /* [rax] = ecx */
            store_guest_reg(&e, &block->exit_contract, 4);
        } else if (op >= 0x58 && op <= 0x5f) {
            stack_address(&e,0,&block->exit_contract);
            byte(&e,0x8b); byte(&e,0x08); /* ecx = [rax] */
            byte(&e,0x83); byte(&e,0xc0); byte(&e,4);
            store_guest_reg(&e, &block->exit_contract, 4);
            store_guest_reg_ecx(&e, &block->exit_contract, op-0x58);
        }
        else if (op >= 0xb8 && op <= 0xbf)
            store_guest_imm(&e, &block->exit_contract, op-0xb8, read32(source+cursor+1));
        else if (op == 0xe8 || op == 0xe9 || op == 0xeb) {
            if (op == 0xe8) push_imm(&e,next,&block->exit_contract);
            uint32_t delta = op == 0xeb ? (uint32_t)(int32_t)(int8_t)source[cursor+1]
                                      : read32(source+cursor+1);
            next += delta;
            terminal = 1;
            if (op == 0xeb || op == 0xe9) {
                block->exit.kind = PW_X86_EXIT_DIRECT_JUMP;
                block->exit.chainable = 1;
                block->exit.target_pc = next;
                emit_chain_exit(&e, count, next, &block->exit_contract,
                                &block->exit.target_patch_offset, &block->exit.target_stub_offset,
                                &block->exit.target_reconcile_offset, &block->exit.target_reconcile_patch_offset);
            }
        } else if (op == 0xc3 || op==0xc2) {
            stack_address(&e,0,&block->exit_contract);
            byte(&e,0x8b); byte(&e,0x08); /* ecx = guest return */
            uint32_t pop=4+(op==0xc2?((uint32_t)source[cursor+1]|(uint32_t)source[cursor+2]<<8):0);
            byte(&e,0x05);word(&e,pop);
            require_condition(&e,0x73); /* unsigned ESP addition must not wrap */
            byte(&e,0x3b);byte(&e,0x47);byte(&e,offsetof(PwX86State,stack_high));
            require_condition(&e,0x76);
            store_guest_reg(&e, &block->exit_contract, 4);
            byte(&e,0x89); byte(&e,0x4f); byte(&e,offsetof(PwX86State,eip));
            terminal = 1;
        }
        if (op != 0xc3 && op!=0xc2 && op!=0xff && !conditional && op != 0xeb && op != 0xe9) store(&e,offsetof(PwX86State,eip),next);
        block->instruction_ends[i]=(uint16_t)(cursor + length);
    }
    if (!block->exit.chainable) {
        block->exit.kind = PW_X86_EXIT_DYNAMIC;
        block->exit.chainable = 0;
        emit_spill_dirty(&e, &block->exit_contract);
        uint8_t n_dirty = popcount8(block->exit_contract.dirty_mask);
        if (n_dirty) {
            byte(&e, 0x83); byte(&e, 0x47); byte(&e, offsetof(PwX86State, reg_stores)); byte(&e, n_dirty);
        }
        byte(&e, 0x83); byte(&e, 0x47); byte(&e, offsetof(PwX86State, step_retired)); byte(&e, (uint8_t)count);
        byte(&e, 0x48); byte(&e, 0xc7); byte(&e, 0x47); byte(&e, offsetof(PwX86State, last_exit_slot)); word(&e, 0);
        success(&e);
    }
    if (e.failed) return PW_ERR_LIMIT;
    block->source_bytes = insts[count-1].cursor + insts[count-1].length;
    block->code_bytes = e.n;
    block->instructions = count;
    return PW_OK;
#undef DECODE_FAIL
}

int pw_x86_translate(const uint8_t *source, size_t bytes, uint32_t pc,
                     uint8_t *output, size_t capacity, PwX86Block *block)
{
    /* The standalone translator has no engine safepoint at which to commit a
     * pending descriptor, so retain its historical eager-EFLAGS contract. */
    return pw_x86_translate_ext(source, bytes, pc, output, capacity, block, 1, 0);
}
