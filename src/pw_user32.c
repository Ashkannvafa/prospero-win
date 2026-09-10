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
