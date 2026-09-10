/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_USER32_H
#define PW_USER32_H
#include "../include/prospero_win.h"

enum { PW_USER32_NAME_MAX=255, PW_USER32_MESSAGE_FIRST=0xc000,
       PW_USER32_MESSAGE_LAST=0xffff };
typedef struct PwUser32Message {
    char name[PW_USER32_NAME_MAX+1];
    uint32_t id;
    unsigned used;
} PwUser32Message;
typedef struct PwUser32Window {
    char class_name[PW_USER32_NAME_MAX+1],title[PW_USER32_NAME_MAX+1];
    uint32_t handle;
    unsigned used;
} PwUser32Window;
typedef struct PwUser32 {
    PwUser32Message *messages;PwUser32Window *windows;
    uint32_t message_capacity,window_capacity,next_message,common_controls;
} PwUser32;

int pw_user32_init(PwUser32 *,PwUser32Message *,uint32_t,
                   PwUser32Window *,uint32_t);
int pw_user32_register_message(PwUser32 *,const char *,uint32_t *);
int pw_user32_find_window(const PwUser32 *,const char *,const char *,uint32_t *);
int pw_user32_init_common_controls(PwUser32 *,uint32_t structure_bytes,uint32_t classes);
#endif
