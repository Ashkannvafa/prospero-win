/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pw_registry_store.h"
#include <assert.h>
#include <string.h>

int main(void)
{
    PwRegistryKey keys[4],loaded_keys[4];PwRegistryValue values[8],loaded_values[8];
    PwRegistry registry,loaded;
    assert(pw_registry_init(&registry,keys,4,values,8)==PW_OK);
    uint32_t key,disposition;
    assert(!pw_registry_create(&registry,PW_HKEY_CURRENT_USER,"Software\\Prospero",&key,&disposition));
    uint32_t score=12345;
    assert(!pw_registry_set(&registry,key,"Score",PW_REG_DWORD,&score,sizeof(score)));
    const char player[]="Player 1";
    assert(!pw_registry_set(&registry,key,"Name",PW_REG_SZ,player,sizeof(player)));
    assert(registry.generation==3);
    assert(!pw_registry_set(&registry,key,"Name",PW_REG_SZ,player,sizeof(player)) &&
           registry.generation==3);
    uint8_t encoded[2048];uint32_t bytes=0;
    assert(pw_registry_encode(&registry,encoded,sizeof(encoded),&bytes)==PW_OK && bytes>24);
    assert(pw_registry_encode(&registry,encoded,23,&bytes)==PW_ERR_LIMIT);

    assert(pw_registry_init(&loaded,loaded_keys,4,loaded_values,8)==PW_OK);
    assert(pw_registry_decode(&loaded,encoded,bytes)==PW_OK && !loaded.generation);
    assert(!pw_registry_open(&loaded,PW_HKEY_CURRENT_USER,"software/prospero",&key));
    uint32_t type=0,size=sizeof(score),result=0;
    assert(!pw_registry_query(&loaded,key,"score",&type,&result,&size) &&
           type==PW_REG_DWORD && size==4 && result==score);
    char name[16];size=sizeof(name);
    assert(!pw_registry_query(&loaded,key,"NAME",&type,name,&size) &&
           type==PW_REG_SZ && size==sizeof(player) && !strcmp(name,player));

    PwRegistryKey before_keys[4];PwRegistryValue before_values[8];
    memcpy(before_keys,loaded_keys,sizeof(before_keys));memcpy(before_values,loaded_values,sizeof(before_values));
    encoded[20]^=1;
    assert(pw_registry_decode(&loaded,encoded,bytes)==PW_ERR_MALFORMED &&
           !memcmp(before_keys,loaded_keys,sizeof(before_keys)) &&
           !memcmp(before_values,loaded_values,sizeof(before_values)));
    encoded[20]^=1;
    assert(pw_registry_decode(&loaded,encoded,bytes-1)==PW_ERR_MALFORMED);
    return 0;
}
