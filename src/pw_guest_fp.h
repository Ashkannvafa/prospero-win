/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_GUEST_FP_H
#define PW_GUEST_FP_H
#include <stdint.h>
/* Raw guest control state, never installed into the host by these services.
 * Arithmetic registers, x87 status/tag stack and instruction execution remain
 * separate future work. Initialize each guest thread before CRT dispatch. */
typedef struct PwGuestFp { uint16_t x87_control; uint32_t mxcsr; unsigned initialized; } PwGuestFp;
void pw_guest_fp_init(PwGuestFp *);
int pw_guest_fp_control(PwGuestFp *,uint32_t value,uint32_t mask,uint32_t *result);
#endif
