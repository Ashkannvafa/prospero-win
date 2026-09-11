/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../native/pw_state_ps5.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    char path[128];snprintf(path,sizeof(path),"/tmp/prospero-win-state-%ld.pwrg",(long)getpid());
    (void)unlink(path);uint8_t buffer[4096];uint32_t bytes=99;
    PwRegistryKey keys[4],other_keys[4];PwRegistryValue values[8],other_values[8];
    PwRegistry registry,other;assert(pw_registry_init(&registry,keys,4,values,8)==PW_OK);
    assert(pw_registry_init(&other,other_keys,4,other_values,8)==PW_OK);
    assert(pw_state_ps5_load_registry(&other,path,buffer,sizeof(buffer),&bytes)==PW_OK && !bytes);
    uint32_t key,disposition,value=7;
    assert(!pw_registry_create(&registry,PW_HKEY_CURRENT_USER,"Software\\Pinball",&key,&disposition));
    assert(!pw_registry_set(&registry,key,"Players",PW_REG_DWORD,&value,4));
    assert(pw_state_ps5_save_registry(&registry,path,buffer,sizeof(buffer),&bytes)==PW_OK && bytes>24);
    uint32_t loaded=0;assert(pw_state_ps5_load_registry(&other,path,buffer,sizeof(buffer),&loaded)==PW_OK && loaded==bytes);
    assert(!pw_registry_open(&other,PW_HKEY_CURRENT_USER,"software\\pinball",&key));
    uint32_t size=4,result=0;assert(!pw_registry_query(&other,key,"players",NULL,&result,&size) && result==7);
    FILE *file=fopen(path,"wb");assert(file);assert(fwrite("bad",1,3,file)==3);assert(!fclose(file));
    assert(pw_state_ps5_load_registry(&other,path,buffer,sizeof(buffer),&loaded)==PW_ERR_MALFORMED);
    assert(!unlink(path));return 0;
}
