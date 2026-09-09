/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pw_registry.h"
#include <assert.h>
#include <string.h>

int main(void)
{
    PwRegistry registry;PwRegistryKey keys[3];PwRegistryValue values[4];
    assert(pw_registry_init(&registry,keys,3,values,4)==PW_OK);
    uint32_t key=0,disposition=0;
    assert(pw_registry_create(&registry,PW_HKEY_CURRENT_USER,"Software/Pinball",&key,&disposition)==0);
    assert(disposition==PW_REG_CREATED_NEW_KEY && key!=PW_HKEY_CURRENT_USER);
    uint32_t same=0;
    assert(pw_registry_create(&registry,PW_HKEY_CURRENT_USER,"software\\PINBALL",&same,&disposition)==0);
    assert(same==key && disposition==PW_REG_OPENED_EXISTING_KEY && keys[0].open_count==2);
    uint32_t number=42;
    assert(pw_registry_set(&registry,key,"Table Version",PW_REG_DWORD,&number,4)==0);
    uint32_t output=0,type=0,size=4;
    assert(pw_registry_query(&registry,same,"table version",&type,&output,&size)==0);
    assert(type==PW_REG_DWORD && size==4 && output==42);
    size=2;output=0xfeedbeef;
    assert(pw_registry_query(&registry,key,"Table Version",&type,&output,&size)==PW_REG_ERROR_MORE_DATA);
    assert(size==4 && output==0xfeedbeef);
    size=0;assert(pw_registry_query(&registry,key,"missing",NULL,NULL,&size)==PW_REG_ERROR_FILE_NOT_FOUND);
    assert(pw_registry_close(&registry,key)==0 && pw_registry_close(&registry,key)==0);
    assert(pw_registry_query(&registry,key,"Table Version",NULL,NULL,&size)==PW_REG_ERROR_INVALID_HANDLE);
    assert(pw_registry_open(&registry,PW_HKEY_CURRENT_USER,"Software\\Pinball",&same)==0);
    assert(pw_registry_open(&registry,same,NULL,&key)==0 && key==same);
    assert(pw_registry_close(&registry,key)==0);
    const char text[]="value";
    assert(pw_registry_set(&registry,same,"",PW_REG_SZ,text,sizeof(text))==0);
    char copy[8]={0};size=sizeof(copy);
    assert(pw_registry_query(&registry,same,"",&type,copy,&size)==0 && !strcmp(copy,text));
    assert(pw_registry_create(&registry,same,"Child",&key,&disposition)==0);
    assert(!strcmp(keys[1].path,"Software\\Pinball\\Child"));
    assert(pw_registry_open(&registry,PW_HKEY_CURRENT_USER,"absent",&key)==PW_REG_ERROR_FILE_NOT_FOUND);
    assert(pw_registry_close(&registry,0x1234)==PW_REG_ERROR_INVALID_HANDLE);
    assert(pw_registry_set(&registry,same,"bad",99,NULL,0)==PW_REG_ERROR_INVALID_PARAMETER);
    return 0;
}
