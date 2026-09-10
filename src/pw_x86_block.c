/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_x86_block.h"
#include "pw_x87.h"
#include <string.h>

/* Context accesses below use signed disp8 encodings. Fail at build time if
 * future state-layout changes would silently address the wrong field. */
_Static_assert(offsetof(PwX86State,eflags)<=127,"context exceeds disp8 layout");

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
static uintptr_t memory_pointer(PwX86State *state,uint32_t address,unsigned write,unsigned width)
{
    uint64_t end=(uint64_t)address+width;
    unsigned permission=write==2?(PW_X86_READ|PW_X86_WRITE):write?PW_X86_WRITE:PW_X86_READ;
    if (!address || (width!=1 && width!=2 && width!=4 && width!=8 && width!=10) ||
        end>0x100000000ull || state->memory_count>PW_X86_MEMORY_REGIONS)
        return 0;
    if(address>=state->stack_low && end<=state->stack_high)return address;
    for(unsigned i=0;i<state->memory_count;i++) {
        const PwX86Memory *m=&state->memory[i];
        if(m->high<=0x100000000ull && address>=m->low && end<=m->high &&
           (m->permissions&permission)==permission)return address;
    }
    return 0;
}
static void memory_address_width(Emitter *e,unsigned write,unsigned width)
{
    /* Effective address is EAX. SysV helper checks the live memory registry.
     * Save context RDI and align native RSP before the call. */
    byte(e,0x89);byte(e,0xc6); /* esi = address */
    byte(e,0xba);word(e,write);
    byte(e,0xb9);word(e,width);
    byte(e,0x57);
    byte(e,0x48);byte(e,0xb8);
    uint64_t target=(uint64_t)(uintptr_t)&memory_pointer;
    word(e,(uint32_t)target);word(e,(uint32_t)(target>>32));
    byte(e,0xff);byte(e,0xd0);byte(e,0x5f);
    byte(e,0x48);byte(e,0x85);byte(e,0xc0);
    require_condition(e,0x75);
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
    byte(e,0xbe);word(e,condition);byte(e,0x57);byte(e,0x48);byte(e,0xb8);
    uint64_t fn=(uint64_t)(uintptr_t)&branch_condition;
    word(e,(uint32_t)fn);word(e,(uint32_t)(fn>>32));
    byte(e,0xff);byte(e,0xd0);byte(e,0x5f);
}
static void conditional_target(Emitter *e,unsigned condition,uint32_t next,uint32_t target)
{
    condition_value(e,condition);
    store(e,offsetof(PwX86State,eip),next);
    byte(e,0x85);byte(e,0xc0);byte(e,0x74);byte(e,7);
    store(e,offsetof(PwX86State,eip),target);
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
static void effective_address(Emitter *e, const Operand *o)
{
    /* EAX arithmetic deliberately wraps at 32 bits; never RIP-relative. */
    byte(e,0xb8); word(e,o->displacement);
    if (o->base>=0) { byte(e,0x03); byte(e,0x47); byte(e,(uint8_t)(o->base*4)); }
    if (o->index>=0) {
        byte(e,0x8b); byte(e,0x57); byte(e,(uint8_t)(o->index*4));
        byte(e,0xc1); byte(e,0xe2); byte(e,(uint8_t)o->scale);
        byte(e,0x01); byte(e,0xd0);
    }
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
        Operand operand;
        unsigned compare=0,alu=7,short_imm=0,word_operand=0,conditional=0,extend=0,setcc=0;
        unsigned x87=0,x87_width=0,x87_write=0,x87_register=0;
        int terminal = 0;
        if(op>=0xd8 && op<=0xdf) {
            int result=decode_operand(source+cursor+1,bytes-cursor-1,&operand);
            if(result!=PW_OK)return result;
            length=1+operand.bytes;
            if(operand.mod!=3) {
                if(op==0xd9 && operand.reg==0){x87=PW_X87_FLD_F32+1;x87_width=4;}
                else if(op==0xd9 && operand.reg==2){x87=PW_X87_FST_F32+1;x87_width=4;x87_write=1;}
                else if(op==0xd9 && operand.reg==3){x87=PW_X87_FSTP_F32+1;x87_width=4;x87_write=1;}
                else if(op==0xdd && operand.reg==0){x87=PW_X87_FLD_F64+1;x87_width=8;}
                else if(op==0xdd && operand.reg==3){x87=PW_X87_FSTP_F64+1;x87_width=8;x87_write=1;}
                else if(op==0xdb && operand.reg==0){x87=PW_X87_FILD_I32+1;x87_width=4;}
                else if(op==0xd8 && operand.reg<=6) {
                    static const unsigned actions[]={PW_X87_FADD_F32,PW_X87_FMUL_F32,
                        PW_X87_FCOM_F32,PW_X87_FCOMP_F32,PW_X87_FSUB_F32,
                        PW_X87_FSUBR_F32,PW_X87_FDIV_F32};
                    x87=actions[operand.reg]+1;x87_width=4;
                } else if(op==0xdc && (operand.reg<=3 || operand.reg==7)) {
                    static const unsigned actions[]={PW_X87_FADD_F64,PW_X87_FMUL_F64,
                        PW_X87_FCOM_F64,PW_X87_FCOMP_F64,0,0,0,PW_X87_FDIVR_F64};
                    x87=actions[operand.reg]+1;x87_width=8;
                }
                else return PW_ERR_UNSUPPORTED;
            } else if(op==0xd9 && operand.reg==0) {
                x87=PW_X87_FLD_ST+1;x87_register=operand.rm+1;
            } else if(op==0xd9 && operand.reg==5 && operand.rm==0)x87=PW_X87_FLD1+1;
            else if(op==0xd9 && operand.reg==5 && operand.rm==6)x87=PW_X87_FLDZ+1;
            else if(op==0xd9 && operand.reg==4 && operand.rm==1)x87=PW_X87_FABS+1;
            else if(op==0xd9 && operand.reg==7 && operand.rm==2)x87=PW_X87_FSQRT+1;
            else if(op==0xdd && operand.reg==3) {
                x87=PW_X87_FSTP_ST+1;x87_register=operand.rm+1;
            } else if(op==0xdf && operand.reg==4 && operand.rm==0)x87=PW_X87_FNSTSW_AX+1;
            else if(op==0xd8 && (operand.reg==0 || operand.reg==1 || operand.reg==2 ||
                                 operand.reg==4 || operand.reg==6)) {
                static const unsigned actions[]={PW_X87_FADD_ST,PW_X87_FMUL_ST,
                    PW_X87_FCOM_ST,0,PW_X87_FSUB_ST,0,PW_X87_FDIV_ST};
                x87=actions[operand.reg]+1;x87_register=operand.rm+1;
            } else if(op==0xde && (operand.reg==0 || operand.reg==7)) {
                x87=(operand.reg==0?PW_X87_FADDP_ST:PW_X87_FDIVP_ST)+1;
                x87_register=operand.rm+1;
            } else if(op==0xda && operand.reg==5 && operand.rm==1)x87=PW_X87_FUCOMPP+1;
            else return PW_ERR_UNSUPPORTED;
        } else if(op==0xc1 || op==0xd1 || op==0xd3) {
            int result=decode_operand(source+cursor+1,bytes-cursor-1,&operand);
            if(result!=PW_OK)return result;
            if(operand.reg!=4 && operand.reg!=5 && operand.reg!=7)return PW_ERR_UNSUPPORTED;
            length=1+operand.bytes+(op==0xc1);
        } else if(op==0x80 || op==0x88 || op==0x8a || op==0xc6 || op==0x38 || op==0x3a || op==0x84 || op==0xf6) {
            int result=decode_operand(source+cursor+1,bytes-cursor-1,&operand);
            if(result!=PW_OK)return result;
            if((op==0x80 && operand.reg!=7) || ((op==0xc6 || op==0xf6) && operand.reg!=0))return PW_ERR_UNSUPPORTED;
            length=1+operand.bytes+(op==0x80 || op==0xc6 || op==0xf6);
        } else if(op==0x3c || op==0xa8 || (op>=0xb0 && op<=0xb7))length=2;
        else if(op>=0x40 && op<=0x4f)length=1;
        else if(op==0x85 || op==0xf7 || op==0xa9) {
            if(op==0xa9){memset(&operand,0,sizeof(operand));operand.mod=3;operand.rm=0;length=5;}
            else {
                int result=decode_operand(source+cursor+1,bytes-cursor-1,&operand);
                if(result!=PW_OK)return result;
                if(op==0xf7 && operand.reg!=0 && operand.reg!=2 && operand.reg!=3)return PW_ERR_UNSUPPORTED;
                length=1+operand.bytes+(op==0xf7 && operand.reg==0?4:0);
            }
        } else if(op==0x66 || op==0x81 || op==0x83 || (op<=0x3d && (op&7)==5)) {
            size_t prefix=op==0x66?1:0;
            if(bytes-cursor<=prefix)return PW_ERR_TRUNCATED;
            unsigned cmpop=source[cursor+prefix];
            unsigned accumulator=cmpop<=0x3d && (cmpop&7)==5;
            if(cmpop!=0x81 && cmpop!=0x83 && !accumulator)return PW_ERR_UNSUPPORTED;
            word_operand=(unsigned)prefix;short_imm=cmpop==0x83;compare=1;
            if(accumulator) {memset(&operand,0,sizeof(operand));operand.mod=3;operand.rm=0;alu=cmpop>>3;}
            else {
                int result=decode_operand(source+cursor+prefix+1,bytes-cursor-prefix-1,&operand);
                if(result!=PW_OK)return result;
                alu=operand.reg;
            }
            length=prefix+1+operand.bytes+(short_imm?1:word_operand?2:4);
        } else if(op>=0x70 && op<=0x7f) {conditional=1;length=2;}
        else if(op==0x0f) {
            if(bytes-cursor<2)return PW_ERR_TRUNCATED;
            if(source[cursor+1]>=0x80 && source[cursor+1]<=0x8f){conditional=1;length=6;}
            else if(source[cursor+1]==0xb6 || source[cursor+1]==0xb7 || source[cursor+1]==0xbe || source[cursor+1]==0xbf || (source[cursor+1]>=0x90 && source[cursor+1]<=0x9f)) {
                int result=decode_operand(source+cursor+2,bytes-cursor-2,&operand);
                if(result!=PW_OK)return result;
                extend=source[cursor+1]>=0xb6;setcc=!extend;
                if(setcc && operand.mod!=3)return PW_ERR_UNSUPPORTED;
                length=2+operand.bytes;
            } else return PW_ERR_UNSUPPORTED;
        } else if (op == 0x64) {
            if (bytes-cursor < 2) return PW_ERR_TRUNCATED;
            if (source[cursor+1]!=0xa1 && source[cursor+1]!=0xa3)
                return PW_ERR_UNSUPPORTED;
            length=6;
        } else if (op == 0x89 || op == 0x8b || op == 0x8d || op==0xc7 ||
                   op==0x01 || op==0x03 || op==0x09 || op==0x0b ||
                   op==0x11 || op==0x13 || op==0x19 || op==0x1b ||
                   op==0x21 || op==0x23 || op==0x29 || op==0x2b ||
                   op==0x31 || op==0x33 || op==0xff || op==0x39 || op==0x3b) {
            int result=decode_operand(source+cursor+1,bytes-cursor-1,&operand);
            if (result!=PW_OK) return result;
            if (op==0x8d && operand.mod==3) return PW_ERR_UNSUPPORTED;
            if (op==0xc7 && operand.reg!=0) return PW_ERR_UNSUPPORTED;
            if (op==0xff && operand.reg!=0 && operand.reg!=1 && operand.reg!=2 && operand.reg!=4 && operand.reg!=6) return PW_ERR_UNSUPPORTED;
            length=1+operand.bytes;
            if (op==0xc7) length+=4;
        } else if (op == 0x6a || op == 0xeb) length = 2;
        else if (op == 0x68 || op == 0xe8 || op == 0xe9 || op==0xa1 || op==0xa3 ||
                 (op >= 0xb8 && op <= 0xbf)) length = 5;
        else if(op==0xc2)length=3;
        else if (op == 0xc3 || op == 0xc9 || op == 0x90 || (op >= 0x50 && op <= 0x5f)) length = 1;
        else return PW_ERR_UNSUPPORTED;
        if (length > bytes-cursor) return PW_ERR_TRUNCATED;
        uint32_t next = pc + (uint32_t)cursor + (uint32_t)length;
        /* Fault exits preserve the PC of the faulting guest instruction. */
        store(&e,offsetof(PwX86State,eip),pc+(uint32_t)cursor);
        if(x87) {
            if(operand.mod!=3){effective_address(&e,&operand);memory_address_width(&e,x87_write,x87_width);}
            x87_call(&e,x87-1,x87_register);
        } else if(op==0xc1 || op==0xd1 || op==0xd3) {
            if(operand.mod==3)load_eax(&e,operand.rm*4);
            else {effective_address(&e,&operand);memory_address_width(&e,2,4);}
            if(op==0xd3){byte(&e,0x8b);byte(&e,0x4f);byte(&e,4);}
            else {byte(&e,0xb9);word(&e,op==0xd1?1:source[cursor+length-1]);}
            byte(&e,0x83);byte(&e,0xe1);byte(&e,31); /* masked count */
            /* r8d selects only defined flags: none for zero, OF only for one.
             * Preserve undefined AF and multi-bit OF deterministically. */
            byte(&e,0x41);byte(&e,0xb8);word(&e,0xc5);
            byte(&e,0xba);word(&e,0);
            byte(&e,0x85);byte(&e,0xc9);
            byte(&e,0x44);byte(&e,0x0f);byte(&e,0x44);byte(&e,0xc2);
            byte(&e,0xba);word(&e,0x8c5);
            byte(&e,0x83);byte(&e,0xf9);byte(&e,1);
            byte(&e,0x44);byte(&e,0x0f);byte(&e,0x44);byte(&e,0xc2);
            byte(&e,0xd3);byte(&e,(operand.mod==3?0xc0:0)|(operand.reg<<3));
            if(operand.mod==3)store_eax(&e,operand.rm*4);
            byte(&e,0x9c);byte(&e,0x5a); /* snapshot native flags */
            byte(&e,0x44);byte(&e,0x21);byte(&e,0xc2);
            byte(&e,0x41);byte(&e,0xf7);byte(&e,0xd0);
            byte(&e,0x44);byte(&e,0x23);byte(&e,0x47);byte(&e,offsetof(PwX86State,eflags));
            byte(&e,0x44);byte(&e,0x09);byte(&e,0xc2);
            byte(&e,0x89);byte(&e,0x57);byte(&e,offsetof(PwX86State,eflags));
        } else if(op>=0x40 && op<=0x4f) {
            unsigned reg=op&7;load_eax(&e,reg*4);
            byte(&e,0xff);byte(&e,op<0x48?0xc0:0xc8);store_eax(&e,reg*4);
            save_arithmetic_flags(&e,0x8d4); /* INC/DEC preserve guest CF. */
        } else if(op>=0xb0 && op<=0xb7) {
            unsigned reg=op&7;
            byte(&e,0xc6);byte(&e,0x47);byte(&e,(reg&3)*4+(reg>>2));byte(&e,source[cursor+1]);
        } else if(op==0x3c || op==0xa8) {
            load_eax(&e,0);byte(&e,op);byte(&e,source[cursor+1]);save_arithmetic_flags(&e,op==0xa8?0x8c5:0x8d5);
        } else if(op==0x80 || op==0x88 || op==0x8a || op==0xc6 || op==0x38 || op==0x3a || op==0x84 || op==0xf6) {
            unsigned dest=(operand.rm&3)*4+(operand.rm>>2),reg=(operand.reg&3)*4+(operand.reg>>2);
            unsigned write=op==0x88 || op==0xc6;
            if(operand.mod!=3){effective_address(&e,&operand);memory_address_width(&e,write,1);}
            if(write) {
                if(op==0xc6) {
                    byte(&e,0xc6);byte(&e,operand.mod==3?0x47:0x00);
                    if(operand.mod==3)byte(&e,dest);
                    byte(&e,source[cursor+length-1]);
                } else {
                    byte(&e,0x0f);byte(&e,0xb6);byte(&e,0x4f);byte(&e,reg);
                    byte(&e,0x88);byte(&e,operand.mod==3?0x4f:0x08);
                    if(operand.mod==3)byte(&e,dest);
                }
            } else {
                byte(&e,0x0f);byte(&e,0xb6);byte(&e,operand.mod==3?0x47:0x00);
                if(operand.mod==3)byte(&e,dest);
                if(op==0x8a){byte(&e,0x88);byte(&e,0x47);byte(&e,reg);}
                else {
                    if(op==0x80 || op==0xf6){byte(&e,op==0xf6?0xa8:0x3c);byte(&e,source[cursor+length-1]);}
                    else if(op==0x3a) {
                        byte(&e,0x89);byte(&e,0xc1);
                        byte(&e,0x0f);byte(&e,0xb6);byte(&e,0x47);byte(&e,reg);
                        byte(&e,0x38);byte(&e,0xc8);
                    } else {byte(&e,op==0x84?0x84:0x3a);byte(&e,0x47);byte(&e,reg);}
                    save_arithmetic_flags(&e,(op==0x84 || op==0xf6)?0x8c5:0x8d5);
                }
            }
        } else if(op==0xc9) {
            load_eax(&e,offsetof(PwX86State,gpr[5]));stack_bounds(&e);
            byte(&e,0x8b);byte(&e,0x08);
            byte(&e,0x83);byte(&e,0xc0);byte(&e,4);
            store_eax(&e,offsetof(PwX86State,gpr[4]));
            byte(&e,0x89);byte(&e,0x4f);byte(&e,offsetof(PwX86State,gpr[5]));
        } else if(op==0xf7 && operand.reg!=0) {
            if(operand.mod==3)load_eax(&e,operand.rm*4);
            else {effective_address(&e,&operand);memory_address_width(&e,2,4);}
            byte(&e,0xf7);byte(&e,(operand.mod==3?0xc0:0)|(operand.reg<<3));
            if(operand.mod==3)store_eax(&e,operand.rm*4);
            if(operand.reg==3)save_arithmetic_flags(&e,0x8d5);
        } else if(op==0x85 || op==0xf7 || op==0xa9) {
            if(operand.mod==3)load_eax(&e,operand.rm*4);
            else {effective_address(&e,&operand);memory_address(&e,0);byte(&e,0x8b);byte(&e,0x00);}
            if(op==0x85){byte(&e,0x85);byte(&e,0x47);byte(&e,operand.reg*4);}
            else {byte(&e,0xa9);word(&e,read32(source+cursor+length-4));}
            save_arithmetic_flags(&e,0x8c5); /* TEST leaves AF undefined; retain it. */
        } else if(setcc) {
            condition_value(&e,source[cursor+1]&15);
            unsigned reg=operand.rm&3,high=operand.rm>=4;
            if(high){byte(&e,0xc1);byte(&e,0xe0);byte(&e,8);}
            byte(&e,0x8b);byte(&e,0x57);byte(&e,reg*4);
            byte(&e,0x81);byte(&e,0xe2);word(&e,high?0xffff00ff:0xffffff00);
            byte(&e,0x09);byte(&e,0xc2);
            byte(&e,0x89);byte(&e,0x57);byte(&e,reg*4);
        } else if(op==0x39 || op==0x3b) {
            if(operand.mod==3)load_eax(&e,operand.rm*4);
            else {effective_address(&e,&operand);memory_address(&e,0);byte(&e,0x8b);byte(&e,0x00);}
            if(op==0x39){byte(&e,0x3b);byte(&e,0x47);byte(&e,operand.reg*4);}
            else {
                byte(&e,0x89);byte(&e,0xc1);load_eax(&e,operand.reg*4);
                byte(&e,0x39);byte(&e,0xc8);
            }
            save_arithmetic_flags(&e,0x8d5);
        } else if(extend) {
            unsigned opcode=source[cursor+1],width=(opcode&1)?2:1;
            if(operand.mod!=3){effective_address(&e,&operand);memory_address_width(&e,0,width);}
            byte(&e,0x0f);byte(&e,opcode);byte(&e,operand.mod==3?0x47:0x00);
            if(operand.mod==3)byte(&e,width==1?(operand.rm&3)*4+(operand.rm>>2):operand.rm*4);
            store_eax(&e,operand.reg*4);
        } else if(compare) {
            if(operand.mod==3)load_eax(&e,operand.rm*4);
            else {
                effective_address(&e,&operand);memory_address_width(&e,alu!=7?2:0,word_operand?2:4);
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
                    if(word_operand)byte(&e,0x66);
                    store_eax(&e,operand.rm*4);
                }
                save_arithmetic_flags(&e,(alu==1 || alu==4 || alu==6)?0x8c5:0x8d5);
            }
        } else if(conditional) {
            unsigned condition=(op==0x0f?source[cursor+1]:op)&15;
            uint32_t delta=op==0x0f?read32(source+cursor+2):(uint32_t)(int32_t)(int8_t)source[cursor+1];
            conditional_target(&e,condition,next,next+delta);terminal=1;
        } else if(op==0xff && operand.reg<2) {
            if(operand.mod==3)load_eax(&e,operand.rm*4);
            else {effective_address(&e,&operand);memory_address_width(&e,2,4);}
            byte(&e,0xff);byte(&e,(operand.mod==3?0xc0:0)|(operand.reg<<3));
            if(operand.mod==3)store_eax(&e,operand.rm*4);
            save_arithmetic_flags(&e,0x8d4);
            store(&e,offsetof(PwX86State,eip),next);
        } else if (op==0xff) {
            if(operand.mod==3)load_eax(&e,operand.rm*4);
            else {
                effective_address(&e,&operand);memory_address(&e,0);
                byte(&e,0x8b);byte(&e,0x00);
            }
            byte(&e,0x89);byte(&e,0xc1); /* preserve target across guest push */
            if(operand.reg==6) {
                /* Source is read using old ESP, before validating/publishing
                 * the destination slot. stack_address preserves ECX. */
                stack_address(&e,1);
                byte(&e,0x89);byte(&e,0x08);store_eax(&e,offsetof(PwX86State,gpr[4]));
                store(&e,offsetof(PwX86State,eip),next);
            } else {
                if(operand.reg==2)push_imm(&e,next);
                byte(&e,0x89);byte(&e,0x4f);byte(&e,offsetof(PwX86State,eip));
                terminal=1;
            }
        } else if (op<=0x33 && ((op&7)==1 || (op&7)==3)) {
            unsigned reverse=(op&7)==1;
            unsigned operation=op>>3;
            unsigned logical=operation==1 || operation==4 || operation==6;
            unsigned dest=reverse?operand.rm:operand.reg;
            unsigned src=reverse?operand.reg:operand.rm;
            if(operand.mod==3) {
                load_eax(&e,dest*4);
                if(operation==2 || operation==3) {
                    byte(&e,0x0f);byte(&e,0xba);byte(&e,0x67);
                    byte(&e,offsetof(PwX86State,eflags));byte(&e,0);
                }
                byte(&e,(uint8_t)(operation*8+3));byte(&e,0x47);byte(&e,src*4);
                store_eax(&e,dest*4);
            } else {
                effective_address(&e,&operand);memory_address_width(&e,reverse?2:0,4);
                if(reverse) {
                    byte(&e,0x8b);byte(&e,0x4f);byte(&e,operand.reg*4);
                    if(operation==2 || operation==3) {
                        byte(&e,0x0f);byte(&e,0xba);byte(&e,0x67);
                        byte(&e,offsetof(PwX86State,eflags));byte(&e,0);
                    }
                    byte(&e,op);byte(&e,0x08); /* [rax] op ecx */
                } else {
                    byte(&e,0x8b);byte(&e,0x08); /* read memory before changing its address register */
                    load_eax(&e,operand.reg*4);
                    if(operation==2 || operation==3) {
                        byte(&e,0x0f);byte(&e,0xba);byte(&e,0x67);
                        byte(&e,offsetof(PwX86State,eflags));byte(&e,0);
                    }
                    byte(&e,(uint8_t)(operation*8+3));byte(&e,0xc1);
                    store_eax(&e,operand.reg*4);
                }
            }
            /* Logical AF is undefined: retain guest AF deterministically. */
            save_arithmetic_flags(&e,logical?0x8c5:0x8d5);
        } else if (op==0xc7) {
            uint32_t value=read32(source+cursor+length-4);
            if (operand.mod==3) store(&e,operand.rm*4,value);
            else {
                effective_address(&e,&operand);memory_address(&e,1);
                byte(&e,0xc7);byte(&e,0x00);word(&e,value);
            }
        } else if (op == 0x64 || op==0xa1 || op==0xa3) {
            unsigned load=op==0xa1 || (op==0x64 && source[cursor+1]==0xa1);
            if(op==0x64)fs_address(&e,read32(source+cursor+2));
            else {byte(&e,0xb8);word(&e,read32(source+cursor+1));memory_address(&e,!load);}
            if (load) {
                byte(&e,0x8b); byte(&e,0x00);
                store_eax(&e,offsetof(PwX86State,gpr[0]));
            } else {
                byte(&e,0x8b); byte(&e,0x4f); byte(&e,0);
                byte(&e,0x89); byte(&e,0x08);
            }
        } else if (op == 0x89 || op == 0x8b || op == 0x8d) {
            if (operand.mod==3) {
                load_eax(&e,(op==0x89 ? operand.reg:operand.rm)*4);
                store_eax(&e,(op==0x89 ? operand.rm:operand.reg)*4);
            } else {
                effective_address(&e,&operand);
                if (op==0x8d) store_eax(&e,operand.reg*4);
                else {
                    memory_address(&e,op==0x89);
                    if (op==0x8b) {
                        byte(&e,0x8b); byte(&e,0x00);
                        store_eax(&e,operand.reg*4);
                    } else {
                        byte(&e,0x8b); byte(&e,0x4f); byte(&e,operand.reg*4);
                        byte(&e,0x89); byte(&e,0x08);
                    }
                }
            }
        } else if (op == 0x6a) push_imm(&e,(uint32_t)(int32_t)(int8_t)source[cursor+1]);
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
        } else if (op == 0xc3 || op==0xc2) {
            stack_address(&e,0);
            byte(&e,0x8b); byte(&e,0x08); /* ecx = guest return */
            uint32_t pop=4+(op==0xc2?((uint32_t)source[cursor+1]|(uint32_t)source[cursor+2]<<8):0);
            byte(&e,0x05);word(&e,pop);
            require_condition(&e,0x73); /* unsigned ESP addition must not wrap */
            byte(&e,0x3b);byte(&e,0x47);byte(&e,offsetof(PwX86State,stack_high));
            require_condition(&e,0x76);
            store_eax(&e,offsetof(PwX86State,gpr[4]));
            byte(&e,0x89); byte(&e,0x4f); byte(&e,offsetof(PwX86State,eip));
            terminal = 1;
        }
        if (op != 0xc3 && op!=0xc2 && op!=0xff && !conditional) store(&e,offsetof(PwX86State,eip),next);
        cursor += length; ++count;
        block->instruction_ends[count-1]=(uint16_t)cursor;
        if (terminal) break;
    }
    success(&e);
    if (e.failed) return PW_ERR_LIMIT;
    block->source_bytes = cursor; block->code_bytes = e.n; block->instructions = count;
    return PW_OK;
}
