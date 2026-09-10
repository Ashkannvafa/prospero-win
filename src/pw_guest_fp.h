/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_GUEST_FP_H
#define PW_GUEST_FP_H
#include <stdint.h>
/* Raw per-guest-thread state, never installed into the host by these services.
 * x87 values use the architectural 80-bit little-endian memory representation;
 * TOP remains encoded in x87_status and two-bit tags use the hardware layout. */
typedef struct PwGuestFp {
    uint16_t x87_control,x87_status,x87_tag,x87_opcode,x87_pending;
    uint32_t x87_ip,x87_dp,mxcsr;
    uint8_t x87_st[8][10];
    unsigned initialized;
} PwGuestFp;
void pw_guest_fp_init(PwGuestFp *);
int pw_guest_fp_control(PwGuestFp *,uint32_t value,uint32_t mask,uint32_t *result);
int pw_guest_x87_push(PwGuestFp *,const uint8_t value[10]);
int pw_guest_x87_peek(const PwGuestFp *,unsigned logical_index,uint8_t value[10]);
int pw_guest_x87_pop(PwGuestFp *,uint8_t value[10]);
#endif
