/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_USER32_H
#define PW_USER32_H
#include "../include/prospero_win.h"

enum { PW_USER32_NAME_MAX=255, PW_USER32_MESSAGE_FIRST=0xc000,
       PW_USER32_MESSAGE_LAST=0xffff, PW_USER32_OBJECT_FIRST=0x10000,
       PW_USER32_ATOM_FIRST=1, PW_USER32_WINDOW_EXTRA_MAX=64,
       PW_USER32_DESKTOP_HANDLE=0x0000ffff };
typedef enum PwUser32ResourceKind { PW_USER32_ICON=1,PW_USER32_SYSTEM_CURSOR=2 } PwUser32ResourceKind;
typedef struct PwUser32Message {
    char name[PW_USER32_NAME_MAX+1];
    uint32_t id;
    unsigned used;
} PwUser32Message;
typedef struct PwUser32Window {
    char class_name[PW_USER32_NAME_MAX+1],title[PW_USER32_NAME_MAX+1];
    uint32_t handle,wndproc,ex_style,style,x,y,width,height,parent,menu,module,param;
    uint32_t extra_bytes;
    uint8_t extra[PW_USER32_WINDOW_EXTRA_MAX];
    unsigned creating,used;
} PwUser32Window;
typedef struct PwUser32Resource {
    char name[PW_USER32_NAME_MAX+1];
    const uint8_t *bytes;
    uint32_t handle,module,type,size,id;
    PwUser32ResourceKind kind;
    unsigned used;
} PwUser32Resource;
typedef struct PwUser32Class {
    char menu_name[PW_USER32_NAME_MAX+1],class_name[PW_USER32_NAME_MAX+1];
    uint32_t style,wndproc,class_extra,window_extra,module,icon,cursor,background;
    uint16_t atom;
    unsigned used;
} PwUser32Class;
typedef struct PwUser32Rect { int32_t left,top,right,bottom; } PwUser32Rect;
typedef struct PwUser32 {
    PwUser32Message *messages;PwUser32Window *windows;
    uint32_t message_capacity,window_capacity,next_message,common_controls;
    PwUser32Resource *resources;
    uint32_t resource_capacity,next_object;
    PwUser32Class *classes;
    uint32_t class_capacity,next_atom;
    uint32_t desktop_width,desktop_height;
    unsigned desktop_configured;
} PwUser32;

int pw_user32_init(PwUser32 *,PwUser32Message *,uint32_t,
                   PwUser32Window *,uint32_t);
int pw_user32_register_message(PwUser32 *,const char *,uint32_t *);
int pw_user32_find_window(const PwUser32 *,const char *,const char *,uint32_t *);
int pw_user32_init_common_controls(PwUser32 *,uint32_t structure_bytes,uint32_t classes);
int pw_user32_init_resources(PwUser32 *,PwUser32Resource *,uint32_t);
int pw_user32_init_classes(PwUser32 *,PwUser32Class *,uint32_t);
int pw_user32_resource(PwUser32 *,PwUser32ResourceKind,uint32_t module,uint32_t type,
                       const char *name,uint32_t id,const uint8_t *,uint32_t,uint32_t *handle);
int pw_user32_register_class(PwUser32 *,const PwUser32Class *,uint16_t *atom);
int pw_user32_find_class(const PwUser32 *,const char *name,uint32_t module,
                         const PwUser32Class **);
int pw_user32_begin_window(PwUser32 *,const PwUser32Window *,uint32_t *slot,
                           uint32_t *handle);
int pw_user32_finish_window(PwUser32 *,uint32_t slot,unsigned commit);
int pw_user32_set_window_long(PwUser32 *,uint32_t handle,int32_t index,
                              uint32_t value,uint32_t *previous);
int pw_user32_configure_desktop(PwUser32 *,uint32_t width,uint32_t height);
int pw_user32_get_window_rect(const PwUser32 *,uint32_t handle,PwUser32Rect *);
#endif
