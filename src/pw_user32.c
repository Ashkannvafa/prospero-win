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
        if(window->used && (!class_name || !strcmp(class_name,window->class_name)) &&
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
