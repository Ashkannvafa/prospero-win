/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pw_user32.h"
#include <assert.h>
#include <string.h>
int main(void)
{
    PwUser32 user;PwUser32Message messages[2];PwUser32Window windows[2];uint32_t value;
    assert(pw_user32_init(&user,messages,2,windows,2)==PW_OK);
    assert(pw_user32_register_message(&user,"PinballMessage",&value)==PW_OK && value==0xc000);
    uint32_t same=0;assert(pw_user32_register_message(&user,"PinballMessage",&same)==PW_OK && same==value);
    assert(pw_user32_register_message(&user,"Other",&value)==PW_OK && value==0xc001);
    assert(pw_user32_register_message(&user,"Overflow",&value)==PW_ERR_LIMIT);
    assert(pw_user32_find_window(&user,"Pinball",NULL,&value)==PW_OK && !value);
    windows[0]=(PwUser32Window){.handle=0x10001,.used=1};
    strcpy(windows[0].class_name,"Pinball");strcpy(windows[0].title,"3D Pinball");
    assert(pw_user32_find_window(&user,"Pinball",NULL,&value)==PW_OK && value==0x10001);
    assert(pw_user32_find_window(&user,NULL,"3D Pinball",&value)==PW_OK && value==0x10001);
    assert(pw_user32_find_window(&user,NULL,NULL,&value)==PW_ERR_PRECONDITION);
    assert(pw_user32_init_common_controls(&user,8,0x16fd)==PW_OK && user.common_controls==0x16fd);
    assert(pw_user32_init_common_controls(&user,8,0x2000)==PW_OK && user.common_controls==0x36fd);
    assert(pw_user32_init_common_controls(&user,4,1)==PW_ERR_UNSUPPORTED);
    return 0;
}
