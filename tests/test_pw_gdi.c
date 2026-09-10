/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pw_gdi.h"
#include <assert.h>
#include <string.h>

int main(void)
{
    PwGdi gdi;PwGdiDc dcs[4];PwGdiSurface surfaces[5];uint8_t pixels[1024];
    assert(pw_gdi_init(NULL,dcs,4,surfaces,5,pixels,sizeof(pixels))==PW_ERR_PRECONDITION);
    assert(pw_gdi_init(&gdi,dcs,4,surfaces,5,pixels,sizeof(pixels))==PW_OK);
    assert(pw_gdi_validate(&gdi)==PW_OK);
    uint32_t screen,screen_again;
    assert(pw_gdi_get_dc(&gdi,0x10000,8,8,&screen)==PW_OK);
    assert(pw_gdi_get_dc(&gdi,0x10000,8,8,&screen_again)==PW_OK);
    assert(screen!=screen_again && pw_gdi_validate(&gdi)==PW_OK);
    assert(pw_gdi_get_dc(&gdi,0x10000,9,8,&screen_again)==PW_ERR_STATE);

    uint32_t memory,bitmap,old;
    assert(pw_gdi_create_compatible_dc(&gdi,screen,&memory)==PW_OK);
    uint32_t layout;
    assert(pw_gdi_get_layout(&gdi,memory,&layout)==PW_OK && !layout);
    assert(pw_gdi_set_layout(&gdi,memory,1,&layout)==PW_OK && !layout);
    assert(pw_gdi_get_layout(&gdi,memory,&layout)==PW_OK && layout==1);
    assert(pw_gdi_set_layout(&gdi,memory,8,&layout)==PW_ERR_UNSUPPORTED && layout==1);
    assert(pw_gdi_get_device_caps(&gdi,memory,PW_GDI_CAP_RASTERCAPS,&layout)==PW_OK &&
           layout==PW_GDI_RC_BITBLT);
    assert(pw_gdi_get_device_caps(&gdi,memory,PW_GDI_CAP_NUMCOLORS,&layout)==PW_OK &&
           layout==UINT32_MAX);
    assert(pw_gdi_get_device_caps(&gdi,memory,99,&layout)==PW_ERR_UNSUPPORTED);
    assert(pw_gdi_select_palette(&gdi,memory,0,0,&layout)==PW_OK && !layout);
    assert(pw_gdi_select_palette(&gdi,memory,1,0,&layout)==PW_ERR_NOT_FOUND);
    assert(pw_gdi_select_palette(&gdi,memory,0,2,&layout)==PW_ERR_PRECONDITION);
    assert(pw_gdi_realize_palette(&gdi,memory,&layout)==PW_OK && !layout);
    assert(pw_gdi_create_compatible_bitmap(&gdi,screen,4,4,&bitmap)==PW_OK);
    assert(pw_gdi_select_bitmap(&gdi,memory,bitmap,&old)==PW_OK && old==PW_GDI_STOCK_BITMAP);
    assert(pw_gdi_delete_object(&gdi,bitmap)==PW_ERR_STATE);
    uint32_t second_memory;
    assert(pw_gdi_create_compatible_dc(&gdi,screen,&second_memory)==PW_OK);
    assert(pw_gdi_select_bitmap(&gdi,second_memory,bitmap,&old)==PW_ERR_STATE);

    PwGdiSurface *bitmap_surface=NULL,*screen_surface=NULL;
    for(unsigned i=0;i<5;i++) {
        if(surfaces[i].used && surfaces[i].handle==bitmap)bitmap_surface=&surfaces[i];
        if(surfaces[i].used && surfaces[i].target==0x10000)screen_surface=&surfaces[i];
    }
    assert(bitmap_surface && screen_surface);
    uint32_t bitmap_offset=bitmap_surface->offset;
    for(unsigned i=0;i<bitmap_surface->bytes;i++)pixels[bitmap_surface->offset+i]=(uint8_t)(i+1);
    assert(pw_gdi_bitblt(&gdi,screen,2,1,4,4,memory,0,0,PW_GDI_ROP_SRCCOPY)==PW_OK);
    for(unsigned row=0;row<4;row++)
        assert(!memcmp(pixels+screen_surface->offset+(row+1)*screen_surface->stride+2*4,
                       pixels+bitmap_surface->offset+row*bitmap_surface->stride,4*4));
    assert(pw_gdi_bitblt(&gdi,screen,0,0,2,2,0,0,0,PW_GDI_ROP_BLACKNESS)==PW_OK);
    uint8_t zero[8]={0};
    assert(!memcmp(pixels+screen_surface->offset,zero,sizeof(zero)));
    assert(!memcmp(pixels+screen_surface->offset+screen_surface->stride,zero,sizeof(zero)));
    assert(pw_gdi_bitblt(&gdi,screen,7,7,2,2,memory,0,0,PW_GDI_ROP_SRCCOPY)==PW_OK);
    assert(pw_gdi_bitblt(&gdi,screen,-2,-2,4,4,memory,0,0,PW_GDI_ROP_SRCCOPY)==PW_OK);
    assert(pw_gdi_bitblt(&gdi,screen,0,0,100,100,memory,0,0,PW_GDI_ROP_BLACKNESS)==PW_OK);
    assert(pw_gdi_bitblt(&gdi,screen,0,0,1,1,memory,0,0,0x1234)==PW_ERR_UNSUPPORTED);
    assert(pw_gdi_resize_target(&gdi,0x10000,4,4)==PW_OK && screen_surface->bytes==64);
    assert(pw_gdi_resize_target(&gdi,0x10000,8,8)==PW_OK && screen_surface->bytes==256);

    assert(pw_gdi_release_dc(&gdi,0x10001,screen)==PW_ERR_STATE);
    assert(pw_gdi_release_dc(&gdi,0x10000,screen)==PW_OK);
    assert(pw_gdi_delete_dc(&gdi,screen_again)==PW_ERR_STATE);
    assert(pw_gdi_delete_dc(&gdi,memory)==PW_OK);
    assert(pw_gdi_delete_object(&gdi,bitmap)==PW_OK);
    uint32_t reused;
    assert(pw_gdi_create_compatible_bitmap(&gdi,screen_again,4,4,&reused)==PW_OK);
    PwGdiSurface *reused_surface=NULL;
    for(unsigned i=0;i<5;i++)if(surfaces[i].used && surfaces[i].handle==reused)reused_surface=&surfaces[i];
    assert(reused_surface && reused_surface->offset==bitmap_offset);
    for(unsigned i=0;i<reused_surface->bytes;i++)assert(!pixels[reused_surface->offset+i]);
    assert(pw_gdi_delete_dc(&gdi,second_memory)==PW_OK);
    assert(pw_gdi_release_dc(&gdi,0x10000,screen_again)==PW_OK);
    assert(pw_gdi_delete_object(&gdi,reused)==PW_OK);

    uint8_t dib[40+8+8]={0};
    dib[0]=40;dib[4]=2;dib[8]=2;dib[12]=1;dib[14]=8;dib[32]=2;
    dib[40]=1;dib[41]=2;dib[42]=3;dib[44]=4;dib[45]=5;dib[46]=6;
    dib[48]=0;dib[49]=1;dib[52]=1;dib[53]=0; /* bottom row, then top row */
    assert(pw_gdi_create_dib_bitmap(&gdi,dib,sizeof(dib),&bitmap)==PW_OK);
    PwGdiSurface *dib_surface=NULL;
    for(unsigned i=0;i<5;i++)if(surfaces[i].used && surfaces[i].handle==bitmap)dib_surface=&surfaces[i];
    assert(dib_surface && dib_surface->width==2 && dib_surface->height==2);
    PwGdiBitmapInfo info;
    assert(pw_gdi_bitmap_info(&gdi,bitmap,&info)==PW_OK && info.width==2 && info.height==2 &&
           info.stride==8 && info.planes==1 && info.bits_per_pixel==32);
    const uint8_t expected[]={4,5,6,255,1,2,3,255,1,2,3,255,4,5,6,255};
    assert(!memcmp(pixels+dib_surface->offset,expected,sizeof(expected)));
    dib[14]=24;
    assert(pw_gdi_create_dib_bitmap(&gdi,dib,sizeof(dib),&old)==PW_ERR_UNSUPPORTED);
    dib[14]=8;dib[32]=3;
    assert(pw_gdi_create_dib_bitmap(&gdi,dib,sizeof(dib),&old)==PW_ERR_TRUNCATED);
    assert(pw_gdi_delete_object(&gdi,bitmap)==PW_OK);

    PwGdiCounts counts;
    assert(pw_gdi_counts(&gdi,&counts)==PW_OK && !counts.dcs && counts.surfaces==1 &&
           counts.target_surfaces==1 && counts.pixel_bytes==256);
    assert(pw_gdi_reset(&gdi)==PW_OK && pw_gdi_validate(&gdi)==PW_OK);
    assert(pw_gdi_counts(&gdi,&counts)==PW_OK && !counts.dcs && !counts.surfaces);

    PwGdiDc one_dc[1];PwGdiSurface one_surface[1];uint8_t tiny[16];PwGdi limited;
    assert(pw_gdi_init(&limited,one_dc,1,one_surface,1,tiny,sizeof(tiny))==PW_OK);
    assert(pw_gdi_get_dc(&limited,1,2,2,&screen)==PW_OK);
    assert(pw_gdi_get_dc(&limited,2,1,1,&memory)==PW_ERR_LIMIT);
    assert(pw_gdi_create_compatible_dc(&limited,screen,&memory)==PW_ERR_LIMIT);
    assert(pw_gdi_create_compatible_bitmap(&limited,screen,1,1,&bitmap)==PW_ERR_LIMIT);
    assert(pw_gdi_resize_target(&limited,1,4,4)==PW_ERR_LIMIT);
    assert(pw_gdi_validate(&limited)==PW_OK);
    return 0;
}
