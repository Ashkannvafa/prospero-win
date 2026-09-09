/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_registry.h"
#include <string.h>

#define HANDLE_BASE 0xd1000000u
#define HANDLE_STEP 16u

static unsigned fold(unsigned c){return c>='A'&&c<='Z'?c+('a'-'A'):c;}
static int equal(const char *a,const char *b)
{
    while(*a && *b){if(fold((unsigned char)*a++)!=fold((unsigned char)*b++))return 0;}
    return !*a && !*b;
}

int pw_registry_init(PwRegistry *r,PwRegistryKey *keys,uint32_t key_capacity,
                     PwRegistryValue *values,uint32_t value_capacity)
{
    if(!r || !keys || !key_capacity || !values || !value_capacity)return PW_ERR_PRECONDITION;
    memset(keys,0,sizeof(*keys)*key_capacity);memset(values,0,sizeof(*values)*value_capacity);
    *r=(PwRegistry){keys,values,key_capacity,value_capacity};return PW_OK;
}

static int key_index(const PwRegistry *r,uint32_t handle,uint32_t *index)
{
    if(!r || !r->keys || !r->values)return 0;
    if(handle<HANDLE_BASE || (handle-HANDLE_BASE)%HANDLE_STEP)return 0;
    uint32_t i=(handle-HANDLE_BASE)/HANDLE_STEP;
    if(i>=r->key_capacity || !r->keys[i].used || r->keys[i].handle!=handle)return 0;
    *index=i;return 1;
}

static uint32_t compose(const PwRegistry *r,uint32_t parent,const char *subkey,
                        char output[PW_REG_PATH_MAX+1])
{
    if(!subkey)return PW_REG_ERROR_INVALID_PARAMETER;
    const char *prefix="";uint32_t ignored;
    if(parent!=PW_HKEY_CURRENT_USER) {
        if(!key_index(r,parent,&ignored))return PW_REG_ERROR_INVALID_HANDLE;
        prefix=r->keys[ignored].path;
    }
    size_t a=strlen(prefix),b=strlen(subkey);
    while(b && (*subkey=='\\' || *subkey=='/')){subkey++;b--;}
    if(a+b+(a&&b?1:0)>PW_REG_PATH_MAX)return PW_REG_ERROR_INVALID_PARAMETER;
    memcpy(output,prefix,a);size_t at=a;
    if(a&&b)output[at++]='\\';
    for(size_t i=0;i<b;i++)output[at++]=subkey[i]=='/'?'\\':subkey[i];
    output[at]=0;return PW_REG_ERROR_SUCCESS;
}

static int find_key(const PwRegistry *r,const char *path,uint32_t *index)
{
    for(uint32_t i=0;i<r->key_capacity;i++)
        if(r->keys[i].used && equal(r->keys[i].path,path)){*index=i;return 1;}
    return 0;
}

uint32_t pw_registry_create(PwRegistry *r,uint32_t parent,const char *subkey,
                            uint32_t *handle,uint32_t *disposition)
{
    if(!r || !handle || !disposition)return PW_REG_ERROR_INVALID_PARAMETER;
    char path[PW_REG_PATH_MAX+1];uint32_t status=compose(r,parent,subkey,path),index;
    if(status)return status;
    if(find_key(r,path,&index)) {
        if(r->keys[index].open_count==UINT32_MAX)return PW_REG_ERROR_ACCESS_DENIED;
        r->keys[index].open_count++;*handle=r->keys[index].handle;
        *disposition=PW_REG_OPENED_EXISTING_KEY;return 0;
    }
    for(index=0;index<r->key_capacity && r->keys[index].used;index++);
    if(index==r->key_capacity)return PW_REG_ERROR_ACCESS_DENIED;
    PwRegistryKey *key=&r->keys[index];memcpy(key->path,path,strlen(path)+1);
    key->handle=HANDLE_BASE+index*HANDLE_STEP;key->open_count=1;key->used=1;
    *handle=key->handle;*disposition=PW_REG_CREATED_NEW_KEY;return 0;
}

uint32_t pw_registry_open(PwRegistry *r,uint32_t parent,const char *subkey,uint32_t *handle)
{
    if(!r || !handle)return PW_REG_ERROR_INVALID_PARAMETER;
    if(!subkey || !*subkey) {
        if(parent==PW_HKEY_CURRENT_USER){*handle=parent;return 0;}
        uint32_t index;
        if(!key_index(r,parent,&index) || !r->keys[index].open_count)
            return PW_REG_ERROR_INVALID_HANDLE;
        if(r->keys[index].open_count==UINT32_MAX)return PW_REG_ERROR_ACCESS_DENIED;
        r->keys[index].open_count++;*handle=parent;return 0;
    }
    char path[PW_REG_PATH_MAX+1];uint32_t status=compose(r,parent,subkey,path),index;
    if(status)return status;
    if(!find_key(r,path,&index))return PW_REG_ERROR_FILE_NOT_FOUND;
    if(r->keys[index].open_count==UINT32_MAX)return PW_REG_ERROR_ACCESS_DENIED;
    r->keys[index].open_count++;*handle=r->keys[index].handle;return 0;
}

uint32_t pw_registry_close(PwRegistry *r,uint32_t handle)
{
    if(handle==PW_HKEY_CURRENT_USER)return 0;
    uint32_t index;
    if(!key_index(r,handle,&index) || !r->keys[index].open_count)
        return PW_REG_ERROR_INVALID_HANDLE;
    r->keys[index].open_count--;return 0;
}

static int live_key(const PwRegistry *r,uint32_t handle,uint32_t *index)
{
    return key_index(r,handle,index) && r->keys[*index].open_count;
}

uint32_t pw_registry_set(PwRegistry *r,uint32_t handle,const char *name,uint32_t type,
                         const void *data,uint32_t size)
{
    uint32_t key;
    if(!r || !name || (size&&!data) || size>PW_REG_DATA_MAX ||
       (type!=PW_REG_DWORD && type!=PW_REG_SZ && type!=PW_REG_BINARY))
        return PW_REG_ERROR_INVALID_PARAMETER;
    if(!live_key(r,handle,&key))return PW_REG_ERROR_INVALID_HANDLE;
    if(strlen(name)>PW_REG_NAME_MAX)return PW_REG_ERROR_INVALID_PARAMETER;
    uint32_t slot=r->value_capacity;
    for(uint32_t i=0;i<r->value_capacity;i++) {
        if(r->values[i].used && r->values[i].key_index==key && equal(r->values[i].name,name))
            {slot=i;break;}
        if(slot==r->value_capacity && !r->values[i].used)slot=i;
    }
    if(slot==r->value_capacity)return PW_REG_ERROR_ACCESS_DENIED;
    PwRegistryValue *value=&r->values[slot];memset(value,0,sizeof(*value));
    memcpy(value->name,name,strlen(name)+1);if(size)memcpy(value->data,data,size);
    value->size=size;value->type=type;value->key_index=key;value->used=1;return 0;
}

uint32_t pw_registry_query(const PwRegistry *r,uint32_t handle,const char *name,
                           uint32_t *type,void *data,uint32_t *size)
{
    uint32_t key;
    if(!r || !name || !size)return PW_REG_ERROR_INVALID_PARAMETER;
    if(!live_key(r,handle,&key))return PW_REG_ERROR_INVALID_HANDLE;
    for(uint32_t i=0;i<r->value_capacity;i++) {
        const PwRegistryValue *value=&r->values[i];
        if(!value->used || value->key_index!=key || !equal(value->name,name))continue;
        uint32_t capacity=*size;*size=value->size;if(type)*type=value->type;
        if(!data)return 0;
        if(capacity<value->size)return PW_REG_ERROR_MORE_DATA;
        if(value->size)memcpy(data,value->data,value->size);
        return 0;
    }
    return PW_REG_ERROR_FILE_NOT_FOUND;
}
