/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_STATE_PS5_H
#define PW_STATE_PS5_H
#include "../src/pw_registry_store.h"

enum { PW_STATE_PS5_MAX_BYTES=256u*1024u };
typedef struct PwStatePs5Report {
    int open_rc,write_rc,fsync_rc,close_rc,rename_rc,unlink_rc;
    uint32_t encoded_bytes,written_bytes;
} PwStatePs5Report;
int pw_state_ps5_load_registry(PwRegistry *,const char *,uint8_t *,uint32_t,uint32_t *);
int pw_state_ps5_save_registry(const PwRegistry *,const char *,uint8_t *,uint32_t,uint32_t *);
int pw_state_ps5_save_registry_ex(const PwRegistry *,const char *,uint8_t *,uint32_t,
                                  uint32_t *,PwStatePs5Report *);

#endif
