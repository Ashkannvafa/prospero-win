/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pw_user32.h"
#include <assert.h>
#include <string.h>
int main(void)
{
    PwUser32 user;PwUser32Message messages[2];PwUser32Window windows[2];
    PwUser32Resource resources[2];PwUser32Class classes[1];uint32_t value;
    assert(pw_user32_init(&user,messages,2,windows,2)==PW_OK);
    assert(pw_user32_init_resources(&user,resources,2)==PW_OK);
    assert(pw_user32_init_classes(&user,classes,1)==PW_OK);
    PwUser32Rect rect;
    assert(pw_user32_get_window_rect(&user,PW_USER32_DESKTOP_HANDLE,&rect)==PW_ERR_STATE);
    assert(pw_user32_configure_desktop(&user,1920,1080)==PW_OK);
    assert(pw_user32_get_window_rect(&user,PW_USER32_DESKTOP_HANDLE,&rect)==PW_OK &&
           rect.left==0 && rect.top==0 && rect.right==1920 && rect.bottom==1080);
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
    const uint8_t icon[]={1,2,3};
    assert(pw_user32_resource(&user,PW_USER32_ICON,0x1000000,14,"ICON_1",0,
                              icon,sizeof(icon),&value)==PW_OK && value==0x10000);
    uint32_t same_icon=0;
    assert(pw_user32_resource(&user,PW_USER32_ICON,0x1000000,14,"ICON_1",0,
                              icon,sizeof(icon),&same_icon)==PW_OK && same_icon==value);
    assert(pw_user32_resource(&user,PW_USER32_SYSTEM_CURSOR,0,0,NULL,32512,NULL,0,
                              &value)==PW_OK && value==0x10001);
    uint32_t previous_cursor=99;
    assert(pw_user32_set_cursor(&user,value,&previous_cursor)==PW_OK && !previous_cursor &&
           user.cursor==value);
    assert(pw_user32_set_cursor(&user,0,&previous_cursor)==PW_OK &&
           previous_cursor==value && !user.cursor);
    assert(pw_user32_set_cursor(&user,0xdeadbeef,&previous_cursor)==PW_ERR_NOT_FOUND);
    assert(pw_user32_resource(&user,PW_USER32_SYSTEM_CURSOR,0,0,NULL,32650,NULL,0,
                              &value)==PW_ERR_LIMIT);
    PwUser32Class descriptor={.style=4104,.wndproc=0x01002000,.module=0x01000000,
        .window_extra=4,
        .icon=0x10000,.cursor=0x10001,.background=16};
    strcpy(descriptor.menu_name,"MENU_1");strcpy(descriptor.class_name,"Pinball");
    uint16_t atom=0;
    PwUser32Class oversized=descriptor;oversized.window_extra=PW_USER32_WINDOW_EXTRA_MAX+1;
    assert(pw_user32_register_class(&user,&oversized,&atom)==PW_ERR_LIMIT && !classes[0].used);
    assert(pw_user32_register_class(&user,&descriptor,&atom)==PW_OK && atom==1);
    const PwUser32Class *found=NULL;
    assert(pw_user32_find_class(&user,"Pinball",0x01000000,&found)==PW_OK &&
           found==&classes[0]);
    assert(pw_user32_find_class(&user,"Missing",0x01000000,&found)==PW_ERR_NOT_FOUND);
    PwUser32Window window={.wndproc=found->wndproc,.module=found->module,.style=0x80000000,
        .extra_bytes=found->window_extra,
        .x=(uint32_t)-10,.y=(uint32_t)-10,.width=1,.height=1};
    strcpy(window.class_name,"Pinball");strcpy(window.title,"Splash");
    uint32_t slot,handle;
    assert(pw_user32_begin_window(&user,&window,&slot,&handle)==PW_OK && slot==1 &&
           handle==0x10002 && windows[1].creating);
    uint32_t menu=0;
    assert(pw_user32_attach_menu(&user,slot,&menu)==PW_OK && menu==0x10003 &&
           windows[1].owns_menu);
    assert(pw_user32_find_window(&user,"Pinball","Splash",&value)==PW_OK && !value);
    assert(pw_user32_finish_window(&user,slot,1)==PW_OK);
    assert(pw_user32_get_menu(&user,handle,&value)==PW_OK && value==menu);
    assert(pw_user32_find_window(&user,"Pinball","Splash",&value)==PW_OK && value==handle);
    assert(pw_user32_get_window_rect(&user,handle,&rect)==PW_OK && rect.left==-10 &&
           rect.top==-10 && rect.right==-9 && rect.bottom==-9);
    uint32_t previous=99;
    assert(pw_user32_move_window(&user,handle,5,6,640,480)==PW_OK);
    assert(pw_user32_get_window_rect(&user,handle,&rect)==PW_OK && rect.left==5 &&
           rect.top==6 && rect.right==645 && rect.bottom==486);
    assert(pw_user32_show_window(&user,handle,8,&previous)==PW_OK && !previous &&
           windows[1].visible && windows[1].needs_paint);
    assert(pw_user32_show_window(&user,handle,8,&previous)==PW_OK && previous==1);
    assert(pw_user32_show_window(&user,handle,0,&previous)==PW_OK && previous==1 &&
           !windows[1].visible);
    assert(pw_user32_show_window(&user,handle,1,&previous)==PW_OK && !previous &&
           windows[1].visible && windows[1].needs_paint);
    assert(pw_user32_show_window(&user,handle,5,&previous)==PW_OK && previous==1);
    assert(pw_user32_show_window(&user,handle,11,&previous)==PW_OK && previous==1);
    assert(pw_user32_show_window(&user,handle,12,&previous)==PW_ERR_UNSUPPORTED);
    assert(pw_user32_set_focus(&user,handle,&previous)==PW_OK && !previous &&
           user.focus_window==handle);
    uint32_t wndproc,needed;
    assert(pw_user32_paint_info(&user,handle,&wndproc,&needed)==PW_OK &&
           wndproc==window.wndproc && needed==1);
    assert(pw_user32_begin_paint(&user,handle,0x20000)==PW_OK && windows[1].painting);
    assert(pw_user32_end_paint(&user,handle,0x20001)==PW_ERR_STATE && windows[1].painting);
    assert(pw_user32_end_paint(&user,handle,0x20000)==PW_OK && !windows[1].painting);
    assert(pw_user32_finish_paint(&user,handle)==PW_OK);
    assert(pw_user32_paint_info(&user,handle,&wndproc,&needed)==PW_OK && !needed);
    previous=99;
    assert(pw_user32_set_window_long(&user,handle,0,0x12345678,&previous)==PW_OK && !previous);
    assert(pw_user32_set_window_long(&user,handle,0,0x87654321,&previous)==PW_OK &&
           previous==0x12345678);
    assert(pw_user32_get_window_long(&user,handle,0,&previous)==PW_OK && previous==0x87654321);
    assert(pw_user32_set_window_long(&user,handle,1,0,&previous)==PW_ERR_PRECONDITION);
    assert(pw_user32_set_window_long(&user,0xdeadbeef,0,0,&previous)==PW_ERR_NOT_FOUND);
    windows[1].creating=1;assert(pw_user32_finish_window(&user,slot,0)==PW_OK && !windows[1].used);
    window.title[0]=0;
    assert(pw_user32_begin_window(&user,&window,&slot,&handle)==PW_OK);
    assert(pw_user32_finish_window(&user,slot,0)==PW_OK);
    assert(pw_user32_register_class(&user,&descriptor,&atom)==PW_ERR_STATE);
    strcpy(descriptor.class_name,"Other");
    assert(pw_user32_register_class(&user,&descriptor,&atom)==PW_ERR_LIMIT);
    uint32_t mapped=99,length=99;char key_name[20];
    assert(pw_user32_map_virtual_key(0x2a,1,&mapped)==PW_OK && mapped==0x10);
    assert(pw_user32_map_virtual_key(0x36,1,&mapped)==PW_OK && mapped==0x10);
    assert(pw_user32_map_virtual_key(0x10,0,&mapped)==PW_OK && mapped==0x2a);
    assert(pw_user32_map_virtual_key('Z',0,&mapped)==PW_OK && mapped==0x2c);
    assert(pw_user32_map_virtual_key('Z',2,&mapped)==PW_OK && mapped=='Z');
    assert(pw_user32_map_virtual_key(0xff,1,&mapped)==PW_OK && !mapped);
    assert(pw_user32_map_virtual_key(0,4,&mapped)==PW_ERR_UNSUPPORTED);
    assert(pw_user32_get_key_name(0x002a0000,key_name,sizeof(key_name),&length)==PW_OK &&
           length==10 && !strcmp(key_name,"Left Shift"));
    assert(pw_user32_get_key_name(0x00360000,key_name,6,&length)==PW_OK &&
           length==5 && !strcmp(key_name,"Right"));
    assert(pw_user32_get_key_name(0x00ff0000,key_name,sizeof(key_name),&length)==PW_OK &&
           !length && !key_name[0]);
    return 0;
}
