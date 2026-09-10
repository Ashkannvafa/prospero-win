/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_user32.h"
#include <string.h>

static int valid_name(const char *name)
{
    if(!name || !*name)return 0;
    size_t n=0;while(n<=PW_USER32_NAME_MAX && name[n])n++;
    return n<=PW_USER32_NAME_MAX;
}
int pw_user32_init(PwUser32 *user,PwUser32Message *messages,uint32_t message_capacity,
                   PwUser32Window *windows,uint32_t window_capacity)
{
    if(!user || !messages || !message_capacity || !windows || !window_capacity)
        return PW_ERR_PRECONDITION;
    memset(messages,0,sizeof(*messages)*message_capacity);
    memset(windows,0,sizeof(*windows)*window_capacity);
    *user=(PwUser32){.messages=messages,.windows=windows,
        .message_capacity=message_capacity,.window_capacity=window_capacity,
        .next_message=PW_USER32_MESSAGE_FIRST};return PW_OK;
}
int pw_user32_register_message(PwUser32 *user,const char *name,uint32_t *id)
{
    if(!user || !user->messages || !id || !valid_name(name))return PW_ERR_PRECONDITION;
    for(uint32_t i=0;i<user->message_capacity;i++)
        if(user->messages[i].used && !strcmp(user->messages[i].name,name)) {
            *id=user->messages[i].id;return PW_OK;
        }
    if(user->next_message>PW_USER32_MESSAGE_LAST)return PW_ERR_LIMIT;
    uint32_t slot=user->message_capacity;
    for(uint32_t i=0;i<user->message_capacity;i++)if(!user->messages[i].used){slot=i;break;}
    if(slot==user->message_capacity)return PW_ERR_LIMIT;
    size_t length=strlen(name);
    memcpy(user->messages[slot].name,name,length+1);
    user->messages[slot].id=user->next_message++;user->messages[slot].used=1;
    *id=user->messages[slot].id;return PW_OK;
}
int pw_user32_find_window(const PwUser32 *user,const char *class_name,
                          const char *title,uint32_t *handle)
{
    if(!user || !user->windows || !handle || (!class_name && !title))
        return PW_ERR_PRECONDITION;
    if((class_name && !valid_name(class_name)) || (title && !valid_name(title)))
        return PW_ERR_PRECONDITION;
    for(uint32_t i=0;i<user->window_capacity;i++) {
        const PwUser32Window *window=&user->windows[i];
        if(window->used && !window->creating && (!class_name || !strcmp(class_name,window->class_name)) &&
           (!title || !strcmp(title,window->title))){*handle=window->handle;return PW_OK;}
    }
    *handle=0;return PW_OK;
}
int pw_user32_init_common_controls(PwUser32 *user,uint32_t bytes,uint32_t classes)
{
    if(!user || !user->messages || !user->windows)return PW_ERR_PRECONDITION;
    if(bytes!=8)return PW_ERR_UNSUPPORTED;
    user->common_controls|=classes;return PW_OK;
}
int pw_user32_init_resources(PwUser32 *user,PwUser32Resource *resources,uint32_t capacity)
{
    if(!user || !resources || !capacity || !user->messages || !user->windows)
        return PW_ERR_PRECONDITION;
    memset(resources,0,sizeof(*resources)*capacity);user->resources=resources;
    user->resource_capacity=capacity;user->next_object=PW_USER32_OBJECT_FIRST;return PW_OK;
}
int pw_user32_init_classes(PwUser32 *user,PwUser32Class *classes,uint32_t capacity)
{
    if(!user || !classes || !capacity || !user->messages || !user->windows ||
       !user->resources)return PW_ERR_PRECONDITION;
    memset(classes,0,sizeof(*classes)*capacity);user->classes=classes;
    user->class_capacity=capacity;user->next_atom=PW_USER32_ATOM_FIRST;return PW_OK;
}
int pw_user32_resource(PwUser32 *user,PwUser32ResourceKind kind,uint32_t module,
                       uint32_t type,const char *name,uint32_t id,const uint8_t *bytes,
                       uint32_t size,uint32_t *handle)
{
    if(!user || !user->resources || !user->resource_capacity || !handle ||
       (kind!=PW_USER32_ICON && kind!=PW_USER32_SYSTEM_CURSOR))return PW_ERR_PRECONDITION;
    if(kind==PW_USER32_ICON && (!module || !type || !valid_name(name) || !bytes || !size))
        return PW_ERR_PRECONDITION;
    if(kind==PW_USER32_SYSTEM_CURSOR && (module || name || bytes || size || !id))
        return PW_ERR_PRECONDITION;
    for(uint32_t i=0;i<user->resource_capacity;i++) {
        PwUser32Resource *r=&user->resources[i];
        if(r->used && r->kind==kind && r->module==module && r->type==type && r->id==id &&
           ((!name && !r->name[0]) || (name && !strcmp(name,r->name)))) {
            *handle=r->handle;return PW_OK;
        }
    }
    uint32_t slot=user->resource_capacity;
    for(uint32_t i=0;i<user->resource_capacity;i++)if(!user->resources[i].used){slot=i;break;}
    if(slot==user->resource_capacity || user->next_object==UINT32_MAX)return PW_ERR_LIMIT;
    PwUser32Resource *r=&user->resources[slot];
    if(name)memcpy(r->name,name,strlen(name)+1);
    r->bytes=bytes;r->module=module;r->type=type;r->size=size;r->id=id;r->kind=kind;
    r->handle=user->next_object++;r->used=1;*handle=r->handle;return PW_OK;
}
int pw_user32_register_class(PwUser32 *user,const PwUser32Class *input,uint16_t *atom)
{
    if(!user || !user->classes || !user->class_capacity || !input || !atom ||
       !valid_name(input->class_name) || (input->menu_name[0] && !valid_name(input->menu_name)) ||
       !input->wndproc || !input->module)return PW_ERR_PRECONDITION;
    if(input->window_extra>PW_USER32_WINDOW_EXTRA_MAX)return PW_ERR_LIMIT;
    for(uint32_t i=0;i<user->class_capacity;i++)
        if(user->classes[i].used && !strcmp(user->classes[i].class_name,input->class_name))
            return PW_ERR_STATE;
    uint32_t slot=user->class_capacity;
    for(uint32_t i=0;i<user->class_capacity;i++)if(!user->classes[i].used){slot=i;break;}
    if(slot==user->class_capacity || !user->next_atom || user->next_atom>0xffff)
        return PW_ERR_LIMIT;
    user->classes[slot]=*input;user->classes[slot].atom=(uint16_t)user->next_atom++;
    user->classes[slot].used=1;*atom=user->classes[slot].atom;return PW_OK;
}
int pw_user32_find_class(const PwUser32 *user,const char *name,uint32_t module,
                         const PwUser32Class **result)
{
    if(!user || !user->classes || !valid_name(name) || !module || !result)
        return PW_ERR_PRECONDITION;
    for(uint32_t i=0;i<user->class_capacity;i++)
        if(user->classes[i].used && user->classes[i].module==module &&
           !strcmp(user->classes[i].class_name,name)){*result=&user->classes[i];return PW_OK;}
    return PW_ERR_NOT_FOUND;
}
int pw_user32_begin_window(PwUser32 *user,const PwUser32Window *input,
                           uint32_t *slot,uint32_t *handle)
{
    if(!user || !user->windows || !user->window_capacity || !input || !slot || !handle ||
       !valid_name(input->class_name) || (input->title[0] && !valid_name(input->title)) || !input->wndproc ||
       !input->module || input->extra_bytes>PW_USER32_WINDOW_EXTRA_MAX)return PW_ERR_PRECONDITION;
    uint32_t free_slot=user->window_capacity;
    for(uint32_t i=0;i<user->window_capacity;i++)if(!user->windows[i].used){free_slot=i;break;}
    if(free_slot==user->window_capacity || user->next_object==UINT32_MAX)return PW_ERR_LIMIT;
    user->windows[free_slot]=*input;user->windows[free_slot].handle=user->next_object++;
    user->windows[free_slot].creating=1;user->windows[free_slot].used=1;
    *slot=free_slot;*handle=user->windows[free_slot].handle;return PW_OK;
}
int pw_user32_finish_window(PwUser32 *user,uint32_t slot,unsigned commit)
{
    if(!user || !user->windows || slot>=user->window_capacity || commit>1 ||
       !user->windows[slot].used || !user->windows[slot].creating)return PW_ERR_PRECONDITION;
    if(commit)user->windows[slot].creating=0;
    else {
        if(user->windows[slot].handle+1==user->next_object)user->next_object--;
        memset(&user->windows[slot],0,sizeof(user->windows[slot]));
    }
    return PW_OK;
}
int pw_user32_set_window_long(PwUser32 *user,uint32_t handle,int32_t index,
                              uint32_t value,uint32_t *previous)
{
    if(!user || !user->windows || !handle || !previous)return PW_ERR_PRECONDITION;
    PwUser32Window *window=NULL;
    for(uint32_t i=0;i<user->window_capacity;i++)
        if(user->windows[i].used && !user->windows[i].creating &&
           user->windows[i].handle==handle){window=&user->windows[i];break;}
    if(!window)return PW_ERR_NOT_FOUND;
    if(index<0 || (uint32_t)index>window->extra_bytes ||
       window->extra_bytes-(uint32_t)index<sizeof(uint32_t))return PW_ERR_PRECONDITION;
    memcpy(previous,window->extra+(uint32_t)index,sizeof(*previous));
    memcpy(window->extra+(uint32_t)index,&value,sizeof(value));
    return PW_OK;
}
int pw_user32_get_window_long(const PwUser32 *user,uint32_t handle,int32_t index,
                              uint32_t *value)
{
    if(!user || !user->windows || !handle || !value)return PW_ERR_PRECONDITION;
    for(uint32_t i=0;i<user->window_capacity;i++) {
        const PwUser32Window *window=&user->windows[i];
        if(!window->used || window->creating || window->handle!=handle)continue;
        if(index<0 || (uint32_t)index>window->extra_bytes ||
           window->extra_bytes-(uint32_t)index<sizeof(uint32_t))return PW_ERR_PRECONDITION;
        memcpy(value,window->extra+(uint32_t)index,sizeof(*value));return PW_OK;
    }
    return PW_ERR_NOT_FOUND;
}
int pw_user32_configure_desktop(PwUser32 *user,uint32_t width,uint32_t height)
{
    if(!user || !user->windows || !width || !height || width>INT32_MAX || height>INT32_MAX)
        return PW_ERR_PRECONDITION;
    user->desktop_width=width;user->desktop_height=height;user->desktop_configured=1;
    return PW_OK;
}
int pw_user32_get_window_rect(const PwUser32 *user,uint32_t handle,PwUser32Rect *rect)
{
    if(!user || !user->windows || !handle || !rect)return PW_ERR_PRECONDITION;
    if(handle==PW_USER32_DESKTOP_HANDLE) {
        if(!user->desktop_configured)return PW_ERR_STATE;
        *rect=(PwUser32Rect){0,0,(int32_t)user->desktop_width,(int32_t)user->desktop_height};
        return PW_OK;
    }
    for(uint32_t i=0;i<user->window_capacity;i++) {
        const PwUser32Window *window=&user->windows[i];
        if(!window->used || window->creating || window->handle!=handle)continue;
        int64_t right=(int64_t)(int32_t)window->x+window->width;
        int64_t bottom=(int64_t)(int32_t)window->y+window->height;
        if(right<INT32_MIN || right>INT32_MAX || bottom<INT32_MIN || bottom>INT32_MAX)
            return PW_ERR_LIMIT;
        *rect=(PwUser32Rect){(int32_t)window->x,(int32_t)window->y,
            (int32_t)right,(int32_t)bottom};return PW_OK;
    }
    return PW_ERR_NOT_FOUND;
}
int pw_user32_move_window(PwUser32 *user,uint32_t handle,int32_t x,int32_t y,
                          uint32_t width,uint32_t height)
{
    if(!user || !user->windows || !handle || !width || !height || width>INT32_MAX ||
       height>INT32_MAX)return PW_ERR_PRECONDITION;
    int64_t right=(int64_t)x+width,bottom=(int64_t)y+height;
    if(right<INT32_MIN || right>INT32_MAX || bottom<INT32_MIN || bottom>INT32_MAX)
        return PW_ERR_LIMIT;
    for(uint32_t i=0;i<user->window_capacity;i++) {
        PwUser32Window *window=&user->windows[i];
        if(window->used && !window->creating && window->handle==handle) {
            window->x=(uint32_t)x;window->y=(uint32_t)y;
            window->width=width;window->height=height;return PW_OK;
        }
    }
    return PW_ERR_NOT_FOUND;
}
int pw_user32_show_window(PwUser32 *user,uint32_t handle,uint32_t command,uint32_t *previous)
{
    if(!user || !user->windows || !handle || !previous)return PW_ERR_PRECONDITION;
    if(command!=8)return PW_ERR_UNSUPPORTED; /* SW_SHOWNA: exact splash path */
    for(uint32_t i=0;i<user->window_capacity;i++) {
        PwUser32Window *window=&user->windows[i];
        if(window->used && !window->creating && window->handle==handle) {
            *previous=window->visible;window->visible=1;window->needs_paint=1;return PW_OK;
        }
    }
    return PW_ERR_NOT_FOUND;
}
int pw_user32_set_focus(PwUser32 *user,uint32_t handle,uint32_t *previous)
{
    if(!user || !user->windows || !handle || !previous)return PW_ERR_PRECONDITION;
    for(uint32_t i=0;i<user->window_capacity;i++) {
        PwUser32Window *window=&user->windows[i];
        if(window->used && !window->creating && window->handle==handle) {
            *previous=user->focus_window;user->focus_window=handle;return PW_OK;
        }
    }
    return PW_ERR_NOT_FOUND;
}
int pw_user32_paint_info(const PwUser32 *user,uint32_t handle,uint32_t *wndproc,
                         uint32_t *needed)
{
    if(!user || !user->windows || !handle || !wndproc || !needed)return PW_ERR_PRECONDITION;
    for(uint32_t i=0;i<user->window_capacity;i++) {
        const PwUser32Window *window=&user->windows[i];
        if(window->used && !window->creating && window->handle==handle) {
            if(!window->wndproc)return PW_ERR_STATE;
            *wndproc=window->wndproc;*needed=window->needs_paint;return PW_OK;
        }
    }
    return PW_ERR_NOT_FOUND;
}
int pw_user32_finish_paint(PwUser32 *user,uint32_t handle)
{
    if(!user || !user->windows || !handle)return PW_ERR_PRECONDITION;
    for(uint32_t i=0;i<user->window_capacity;i++) {
        PwUser32Window *window=&user->windows[i];
        if(window->used && !window->creating && window->handle==handle) {
            window->needs_paint=0;return PW_OK;
        }
    }
    return PW_ERR_NOT_FOUND;
}
int pw_user32_begin_paint(PwUser32 *user,uint32_t handle,uint32_t dc)
{
    if(!user || !user->windows || !handle || !dc)return PW_ERR_PRECONDITION;
    for(uint32_t i=0;i<user->window_capacity;i++) {
        PwUser32Window *window=&user->windows[i];
        if(window->used && !window->creating && window->handle==handle) {
            if(window->painting)return PW_ERR_STATE;
            window->paint_dc=dc;window->painting=1;return PW_OK;
        }
    }
    return PW_ERR_NOT_FOUND;
}
int pw_user32_end_paint(PwUser32 *user,uint32_t handle,uint32_t dc)
{
    if(!user || !user->windows || !handle || !dc)return PW_ERR_PRECONDITION;
    for(uint32_t i=0;i<user->window_capacity;i++) {
        PwUser32Window *window=&user->windows[i];
        if(window->used && !window->creating && window->handle==handle) {
            if(!window->painting || window->paint_dc!=dc)return PW_ERR_STATE;
            window->paint_dc=0;window->painting=0;return PW_OK;
        }
    }
    return PW_ERR_NOT_FOUND;
}
int pw_user32_check_paint(const PwUser32 *user,uint32_t handle,uint32_t dc)
{
    if(!user || !user->windows || !handle || !dc)return PW_ERR_PRECONDITION;
    for(uint32_t i=0;i<user->window_capacity;i++) {
        const PwUser32Window *window=&user->windows[i];
        if(window->used && !window->creating && window->handle==handle)
            return window->painting && window->paint_dc==dc?PW_OK:PW_ERR_STATE;
    }
    return PW_ERR_NOT_FOUND;
}
