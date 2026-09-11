/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_REGISTRY_STORE_H
#define PW_REGISTRY_STORE_H
#include "pw_registry.h"

/* Stable little-endian process-state format. Handles and open counts are
 * deliberately excluded; a new process recreates those transient objects. */
int pw_registry_encode(const PwRegistry *,uint8_t *,uint32_t,uint32_t *);
int pw_registry_decode(PwRegistry *,const uint8_t *,uint32_t);

#endif
