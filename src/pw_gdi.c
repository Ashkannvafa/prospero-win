/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_gdi.h"
#include <string.h>

static uint32_t align4(uint32_t value){return (value+3u)&~3u;}
static PwGdiDc *find_dc(PwGdi *gdi,uint32_t handle)
{
    if(!gdi || !handle)return NULL;
    for(uint32_t i=0;i<gdi->dc_capacity;i++)
        if(gdi->dcs[i].used && gdi->dcs[i].handle==handle)return &gdi->dcs[i];
    return NULL;
}
static PwGdiSurface *find_bitmap(PwGdi *gdi,uint32_t handle)
{
    if(!gdi || !handle || handle==PW_GDI_STOCK_BITMAP)return NULL;
    for(uint32_t i=0;i<gdi->surface_capacity;i++)
        if(gdi->surfaces[i].used && gdi->surfaces[i].kind==PW_GDI_BITMAP &&
           gdi->surfaces[i].handle==handle)return &gdi->surfaces[i];
    return NULL;
}
static PwGdiPalette *find_palette(PwGdi *gdi,uint32_t handle)
{
    if(!gdi || !handle)return NULL;
    for(uint32_t i=0;i<PW_GDI_PALETTE_CAPACITY;i++)
        if(gdi->palettes[i].used && gdi->palettes[i].handle==handle)return &gdi->palettes[i];
    return NULL;
}
static int free_dc_slot(const PwGdi *gdi,uint32_t *slot)
{
    for(uint32_t i=0;i<gdi->dc_capacity;i++)if(!gdi->dcs[i].used){*slot=i;return PW_OK;}
    return PW_ERR_LIMIT;
}
static int free_surface_slot(const PwGdi *gdi,uint32_t *slot)
{
    for(uint32_t i=0;i<gdi->surface_capacity;i++)
        if(!gdi->surfaces[i].used){*slot=i;return PW_OK;}
    return PW_ERR_LIMIT;
}
static int surface_bytes(uint32_t width,uint32_t height,uint32_t *stride,uint32_t *bytes)
{
    if(!width || !height || width>UINT32_MAX/4)return PW_ERR_PRECONDITION;
    uint32_t row=width*4;
    if(height>UINT32_MAX/row)return PW_ERR_LIMIT;
    *stride=row;*bytes=row*height;return PW_OK;
}
static int pixel_gap_ignoring(const PwGdi *gdi,uint32_t bytes,uint32_t ignored,uint32_t *offset)
{
    uint32_t candidate=0;
    for(;;) {
        uint64_t end=(uint64_t)candidate+bytes;
        if(end>gdi->pixel_capacity)return PW_ERR_LIMIT;
        unsigned moved=0;
        for(uint32_t i=0;i<gdi->surface_capacity;i++) {
            if(i==ignored)continue;
            const PwGdiSurface *surface=&gdi->surfaces[i];
            if(!surface->used)continue;
            uint64_t live_end=(uint64_t)surface->offset+surface->bytes;
            if(candidate<live_end && end>surface->offset) {
                if(live_end>UINT32_MAX)return PW_ERR_STATE;
                candidate=align4((uint32_t)live_end);moved=1;break;
            }
        }
        if(!moved){*offset=candidate;return PW_OK;}
    }
}
static int pixel_gap(const PwGdi *gdi,uint32_t bytes,uint32_t *offset)
{return pixel_gap_ignoring(gdi,bytes,PW_GDI_NO_SURFACE,offset);}
static int next_handle(PwGdi *gdi,uint32_t *handle)
{
    if(gdi->next_handle==UINT32_MAX || gdi->next_handle==PW_GDI_STOCK_BITMAP)
        return PW_ERR_LIMIT;
    *handle=gdi->next_handle++;return PW_OK;
}
static int allocate_surface(PwGdi *gdi,PwGdiSurfaceKind kind,uint32_t target,
                            uint32_t width,uint32_t height,uint32_t *slot,uint32_t *handle)
{
    uint32_t free_slot,stride,bytes,offset,new_handle=0;int status;
    if((status=free_surface_slot(gdi,&free_slot))!=PW_OK ||
       (status=surface_bytes(width,height,&stride,&bytes))!=PW_OK ||
       (status=pixel_gap(gdi,bytes,&offset))!=PW_OK)return status;
    if(kind==PW_GDI_BITMAP && (status=next_handle(gdi,&new_handle))!=PW_OK)return status;
    PwGdiSurface surface={.handle=new_handle,.target=target,.width=width,.height=height,
        .stride=stride,.offset=offset,.bytes=bytes,.kind=kind,.used=1};
    memset(gdi->pixels+offset,0,bytes);gdi->surfaces[free_slot]=surface;
    *slot=free_slot;if(handle)*handle=new_handle;return PW_OK;
}
static int dc_surface(PwGdi *gdi,PwGdiDc *dc,PwGdiSurface **surface)
{
    if(dc->surface==PW_GDI_NO_SURFACE || dc->surface>=gdi->surface_capacity ||
       !gdi->surfaces[dc->surface].used)return PW_ERR_STATE;
    *surface=&gdi->surfaces[dc->surface];return PW_OK;
}
int pw_gdi_init(PwGdi *gdi,PwGdiDc *dcs,uint32_t dc_capacity,
                PwGdiSurface *surfaces,uint32_t surface_capacity,
                uint8_t *pixels,uint32_t pixel_capacity)
{
    if(!gdi || !dcs || !dc_capacity || !surfaces || !surface_capacity || !pixels ||
       !pixel_capacity)return PW_ERR_PRECONDITION;
    memset(dcs,0,sizeof(*dcs)*dc_capacity);
    memset(surfaces,0,sizeof(*surfaces)*surface_capacity);
    *gdi=(PwGdi){.dcs=dcs,.surfaces=surfaces,.pixels=pixels,
        .dc_capacity=dc_capacity,.surface_capacity=surface_capacity,
        .pixel_capacity=pixel_capacity,.next_handle=PW_GDI_HANDLE_FIRST,.system_palette_use=1};
    return PW_OK;
}
int pw_gdi_get_dc(PwGdi *gdi,uint32_t owner,uint32_t width,uint32_t height,uint32_t *dc)
{
    if(!gdi || !gdi->dcs || !gdi->surfaces || !gdi->pixels || !owner || !dc)
        return PW_ERR_PRECONDITION;
    uint32_t dc_slot;int status=free_dc_slot(gdi,&dc_slot);if(status!=PW_OK)return status;
    uint32_t surface_slot=PW_GDI_NO_SURFACE;
    for(uint32_t i=0;i<gdi->surface_capacity;i++) {
        PwGdiSurface *surface=&gdi->surfaces[i];
        if(surface->used && surface->kind==PW_GDI_TARGET_SURFACE && surface->target==owner) {
            if(surface->width!=width || surface->height!=height)return PW_ERR_STATE;
            surface_slot=i;break;
        }
    }
    unsigned made_surface=surface_slot==PW_GDI_NO_SURFACE;
    if(made_surface && (status=allocate_surface(gdi,PW_GDI_TARGET_SURFACE,owner,width,height,
                                                &surface_slot,NULL))!=PW_OK)return status;
    uint32_t handle;
    if((status=next_handle(gdi,&handle))!=PW_OK) {
        if(made_surface)memset(&gdi->surfaces[surface_slot],0,sizeof(gdi->surfaces[surface_slot]));
        return status;
    }
    gdi->dcs[dc_slot]=(PwGdiDc){.handle=handle,.owner_window=owner,.surface=surface_slot,
        .kind=PW_GDI_WINDOW_DC,.used=1};*dc=handle;return PW_OK;
}
int pw_gdi_release_dc(PwGdi *gdi,uint32_t owner,uint32_t handle)
{
    PwGdiDc *dc=find_dc(gdi,handle);
    if(!owner || !dc)return PW_ERR_NOT_FOUND;
    if(dc->kind!=PW_GDI_WINDOW_DC || dc->owner_window!=owner)return PW_ERR_STATE;
    PwGdiPalette *palette=find_palette(gdi,dc->selected_palette);
    if(palette)palette->selected_by--;
    memset(dc,0,sizeof(*dc));return PW_OK;
}
int pw_gdi_create_compatible_dc(PwGdi *gdi,uint32_t source,uint32_t *result)
{
    if(!gdi || !result)return PW_ERR_PRECONDITION;
    if(!find_dc(gdi,source))return PW_ERR_NOT_FOUND;
    uint32_t slot,handle;int status=free_dc_slot(gdi,&slot);if(status!=PW_OK)return status;
    if((status=next_handle(gdi,&handle))!=PW_OK)return status;
    gdi->dcs[slot]=(PwGdiDc){.handle=handle,.compatible_dc=source,
        .surface=PW_GDI_NO_SURFACE,.selected_bitmap=PW_GDI_STOCK_BITMAP,
        .kind=PW_GDI_MEMORY_DC,.used=1};*result=handle;return PW_OK;
}
int pw_gdi_create_compatible_bitmap(PwGdi *gdi,uint32_t source,uint32_t width,
                                    uint32_t height,uint32_t *bitmap)
{
    if(!gdi || !bitmap)return PW_ERR_PRECONDITION;
    if(!find_dc(gdi,source))return PW_ERR_NOT_FOUND;
    uint32_t slot;return allocate_surface(gdi,PW_GDI_BITMAP,0,width,height,&slot,bitmap);
}
static uint16_t read16(const uint8_t *p){return (uint16_t)p[0]|(uint16_t)p[1]<<8;}
static uint32_t read32(const uint8_t *p)
{return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
int pw_gdi_create_dib_bitmap(PwGdi *gdi,const uint8_t *dib,uint32_t dib_bytes,
                             uint32_t *bitmap)
{
    if(!gdi || !dib || !bitmap)return PW_ERR_PRECONDITION;
    if(dib_bytes<40)return PW_ERR_TRUNCATED;
    uint32_t header=read32(dib),raw_width=read32(dib+4),raw_height=read32(dib+8);
    int32_t width=(int32_t)raw_width,height=(int32_t)raw_height;
    uint16_t planes=read16(dib+12),bits=read16(dib+14);
    uint32_t compression=read32(dib+16),colors=read32(dib+32);
    if(header<40 || header>dib_bytes || width<=0 || !height || height==INT32_MIN ||
       planes!=1 || bits!=8 || compression!=0)return PW_ERR_UNSUPPORTED;
    uint32_t rows=height<0?(uint32_t)-height:(uint32_t)height;
    if(!colors)colors=256;
    if(colors>256)return PW_ERR_MALFORMED;
    uint64_t table_end=(uint64_t)header+(uint64_t)colors*4;
    uint64_t row_bytes=((uint64_t)(uint32_t)width*8+31)/32*4;
    uint64_t source_bytes=row_bytes*rows;
    if(table_end>dib_bytes || source_bytes>dib_bytes-table_end)return PW_ERR_TRUNCATED;
    uint32_t slot,handle;int status=allocate_surface(gdi,PW_GDI_BITMAP,0,(uint32_t)width,
                                                      rows,&slot,&handle);
    if(status!=PW_OK)return status;
    PwGdiSurface *surface=&gdi->surfaces[slot];uint8_t *destination=gdi->pixels+surface->offset;
    const uint8_t *palette=dib+header,*source=dib+(uint32_t)table_end;
    for(uint32_t y=0;y<rows;y++) {
        uint32_t source_y=height>0?rows-1-y:y;
        const uint8_t *row=source+source_y*(uint32_t)row_bytes;
        uint8_t *out=destination+y*surface->stride;
        for(uint32_t x=0;x<(uint32_t)width;x++) {
            uint32_t index=row[x];
            if(index>=colors) {
                memset(destination,0,surface->bytes);memset(surface,0,sizeof(*surface));
                if(handle+1==gdi->next_handle)gdi->next_handle--;
                return PW_ERR_MALFORMED;
            }
            out[x*4]=palette[index*4];out[x*4+1]=palette[index*4+1];
            out[x*4+2]=palette[index*4+2];out[x*4+3]=255;
        }
    }
    *bitmap=handle;return PW_OK;
}
int pw_gdi_create_palette(PwGdi *gdi,uint16_t version,uint16_t count,
                          const uint8_t entries[][4],uint32_t *palette)
{
    if(!gdi || !entries || !palette || version!=0x300 || !count ||
       count>PW_GDI_PALETTE_ENTRIES)return PW_ERR_PRECONDITION;
    uint32_t slot=PW_GDI_PALETTE_CAPACITY;
    for(uint32_t i=0;i<PW_GDI_PALETTE_CAPACITY;i++)
        if(!gdi->palettes[i].used){slot=i;break;}
    if(slot==PW_GDI_PALETTE_CAPACITY)return PW_ERR_LIMIT;
    uint32_t handle;int status=next_handle(gdi,&handle);if(status!=PW_OK)return status;
    PwGdiPalette value={.handle=handle,.version=version,.count=count,.used=1};
    memcpy(value.entries,entries,(size_t)count*4);gdi->palettes[slot]=value;
    *palette=handle;return PW_OK;
}
int pw_gdi_set_palette_entries(PwGdi *gdi,uint32_t handle,uint32_t start,
                               uint32_t count,const uint8_t entries[][4],uint32_t *written)
{
    if(!gdi || !entries || !written)return PW_ERR_PRECONDITION;
    PwGdiPalette *palette=find_palette(gdi,handle);if(!palette)return PW_ERR_NOT_FOUND;
    if(start>palette->count || count>palette->count-start)return PW_ERR_PRECONDITION;
    memcpy(palette->entries+start,entries,(size_t)count*4);*written=count;return PW_OK;
}
int pw_gdi_resize_palette(PwGdi *gdi,uint32_t handle,uint32_t count)
{
    if(!gdi || !count || count>PW_GDI_PALETTE_ENTRIES)return PW_ERR_PRECONDITION;
    PwGdiPalette *palette=find_palette(gdi,handle);if(!palette)return PW_ERR_NOT_FOUND;
    if(count>palette->count)
        memset(palette->entries+palette->count,0,(count-palette->count)*sizeof(palette->entries[0]));
    palette->count=(uint16_t)count;return PW_OK;
}
int pw_gdi_stock_object(uint32_t index,uint32_t *object)
{
    if(!object)return PW_ERR_PRECONDITION;
    if(index>19 || index==9)return PW_ERR_NOT_FOUND;
    *object=PW_GDI_STOCK_OBJECT_BASE+index;return PW_OK;
}
int pw_gdi_select_bitmap(PwGdi *gdi,uint32_t handle,uint32_t bitmap,uint32_t *previous)
{
    if(!gdi || !previous)return PW_ERR_PRECONDITION;
    PwGdiDc *dc=find_dc(gdi,handle);if(!dc)return PW_ERR_NOT_FOUND;
    if(dc->kind!=PW_GDI_MEMORY_DC)return PW_ERR_STATE;
    PwGdiSurface *next=find_bitmap(gdi,bitmap);if(!next)return PW_ERR_NOT_FOUND;
    if(next->selected_by && dc->selected_bitmap!=bitmap)return PW_ERR_STATE;
    PwGdiSurface *old=find_bitmap(gdi,dc->selected_bitmap);
    *previous=dc->selected_bitmap;
    if(old && old!=next)old->selected_by--;
    if(old!=next)next->selected_by++;
    dc->selected_bitmap=bitmap;
    dc->surface=(uint32_t)(next-gdi->surfaces);return PW_OK;
}
int pw_gdi_delete_dc(PwGdi *gdi,uint32_t handle)
{
    PwGdiDc *dc=find_dc(gdi,handle);if(!dc)return PW_ERR_NOT_FOUND;
    if(dc->kind!=PW_GDI_MEMORY_DC)return PW_ERR_STATE;
    PwGdiSurface *selected=find_bitmap(gdi,dc->selected_bitmap);
    if(selected)selected->selected_by--;
    PwGdiPalette *palette=find_palette(gdi,dc->selected_palette);
    if(palette)palette->selected_by--;
    memset(dc,0,sizeof(*dc));return PW_OK;
}
int pw_gdi_delete_object(PwGdi *gdi,uint32_t object)
{
    PwGdiSurface *surface=find_bitmap(gdi,object);
    if(surface) {
        if(surface->selected_by)return PW_ERR_STATE;
        memset(gdi->pixels+surface->offset,0,surface->bytes);
        memset(surface,0,sizeof(*surface));return PW_OK;
    }
    PwGdiPalette *palette=find_palette(gdi,object);if(!palette)return PW_ERR_NOT_FOUND;
    if(palette->selected_by)return PW_ERR_STATE;
    memset(palette,0,sizeof(*palette));return PW_OK;
}
int pw_gdi_get_layout(PwGdi *gdi,uint32_t handle,uint32_t *layout)
{
    if(!gdi || !layout)return PW_ERR_PRECONDITION;
    PwGdiDc *dc=find_dc(gdi,handle);if(!dc)return PW_ERR_NOT_FOUND;
    *layout=dc->layout;return PW_OK;
}
int pw_gdi_set_layout(PwGdi *gdi,uint32_t handle,uint32_t layout,uint32_t *previous)
{
    if(!gdi || !previous)return PW_ERR_PRECONDITION;
    if(layout&~1u)return PW_ERR_UNSUPPORTED; /* only LAYOUT_RTL is source-confirmed */
    PwGdiDc *dc=find_dc(gdi,handle);if(!dc)return PW_ERR_NOT_FOUND;
    *previous=dc->layout;dc->layout=layout;return PW_OK;
}
int pw_gdi_get_device_caps(PwGdi *gdi,uint32_t handle,uint32_t index,uint32_t *value)
{
    if(!gdi || !value)return PW_ERR_PRECONDITION;
    if(!find_dc(gdi,handle))return PW_ERR_NOT_FOUND;
    /* Deterministic host-trace profile: 32-bit true color with BitBlt and no
     * palette device. NUMCOLORS is -1 for displays above 8 bpp. */
    if(index==PW_GDI_CAP_RASTERCAPS)*value=PW_GDI_RC_BITBLT;
    else if(index==PW_GDI_CAP_NUMCOLORS)*value=UINT32_MAX;
    else return PW_ERR_UNSUPPORTED;
    return PW_OK;
}
int pw_gdi_bitmap_info(PwGdi *gdi,uint32_t bitmap,PwGdiBitmapInfo *info)
{
    if(!gdi || !info)return PW_ERR_PRECONDITION;
    PwGdiSurface *surface=find_bitmap(gdi,bitmap);if(!surface)return PW_ERR_NOT_FOUND;
    *info=(PwGdiBitmapInfo){surface->width,surface->height,surface->stride,1,32};return PW_OK;
}
int pw_gdi_resize_target(PwGdi *gdi,uint32_t owner,uint32_t width,uint32_t height)
{
    if(!gdi || !owner)return PW_ERR_PRECONDITION;
    for(uint32_t i=0;i<gdi->surface_capacity;i++) {
        PwGdiSurface *surface=&gdi->surfaces[i];
        if(!surface->used || surface->kind!=PW_GDI_TARGET_SURFACE || surface->target!=owner)continue;
        uint32_t stride,bytes,offset=surface->offset;int status=surface_bytes(width,height,&stride,&bytes);
        if(status!=PW_OK)return status;
        if(bytes>surface->bytes && (status=pixel_gap_ignoring(gdi,bytes,i,&offset))!=PW_OK)return status;
        if(offset!=surface->offset)memset(gdi->pixels+surface->offset,0,surface->bytes);
        memset(gdi->pixels+offset,0,bytes);
        surface->offset=offset;surface->bytes=bytes;surface->stride=stride;
        surface->width=width;surface->height=height;return PW_OK;
    }
    return PW_OK;
}
int pw_gdi_destroy_target(PwGdi *gdi,uint32_t owner)
{
    if(!gdi || !owner)return PW_ERR_PRECONDITION;
    for(uint32_t i=0;i<gdi->dc_capacity;i++)
        if(gdi->dcs[i].used && gdi->dcs[i].kind==PW_GDI_WINDOW_DC &&
           gdi->dcs[i].owner_window==owner)return PW_ERR_STATE;
    for(uint32_t i=0;i<gdi->surface_capacity;i++) {
        PwGdiSurface *surface=&gdi->surfaces[i];
        if(surface->used && surface->kind==PW_GDI_TARGET_SURFACE && surface->target==owner) {
            memset(gdi->pixels+surface->offset,0,surface->bytes);
            memset(surface,0,sizeof(*surface));return PW_OK;
        }
    }
    return PW_OK;
}
int pw_gdi_target_view(const PwGdi *gdi,uint32_t owner,PwGdiTargetView *view)
{
    if(!gdi || !gdi->surfaces || !gdi->pixels || !owner || !view)
        return PW_ERR_PRECONDITION;
    for(uint32_t i=0;i<gdi->surface_capacity;i++) {
        const PwGdiSurface *surface=&gdi->surfaces[i];
        if(!surface->used || surface->kind!=PW_GDI_TARGET_SURFACE ||
           surface->target!=owner)continue;
        if(surface->offset>gdi->pixel_capacity ||
           surface->bytes>gdi->pixel_capacity-surface->offset)return PW_ERR_STATE;
        *view=(PwGdiTargetView){gdi->pixels+surface->offset,surface->width,
            surface->height,surface->stride,surface->bytes};
        return PW_OK;
    }
    return PW_ERR_NOT_FOUND;
}
int pw_gdi_select_palette(PwGdi *gdi,uint32_t handle,uint32_t palette,uint32_t background,
                          uint32_t *previous)
{
    if(!gdi || !previous)return PW_ERR_PRECONDITION;
    if(background>1)return PW_ERR_PRECONDITION;
    PwGdiDc *dc=find_dc(gdi,handle);if(!dc)return PW_ERR_NOT_FOUND;
    PwGdiPalette *next=palette?find_palette(gdi,palette):NULL;
    if(palette && !next)return PW_ERR_NOT_FOUND;
    PwGdiPalette *old=find_palette(gdi,dc->selected_palette);
    *previous=dc->selected_palette;
    if(old && old!=next)old->selected_by--;
    if(next && old!=next)next->selected_by++;
    dc->selected_palette=palette;return PW_OK;
}
int pw_gdi_realize_palette(PwGdi *gdi,uint32_t handle,uint32_t *changed)
{
    if(!gdi || !changed)return PW_ERR_PRECONDITION;
    if(!find_dc(gdi,handle))return PW_ERR_NOT_FOUND;
    *changed=0;return PW_OK;
}
int pw_gdi_bitblt(PwGdi *gdi,uint32_t destination_handle,int32_t x,int32_t y,
                  uint32_t width,uint32_t height,uint32_t source_handle,
                  int32_t source_x,int32_t source_y,uint32_t rop)
{
    if(!gdi)return PW_ERR_PRECONDITION;
    if(rop!=PW_GDI_ROP_SRCCOPY && rop!=PW_GDI_ROP_BLACKNESS)return PW_ERR_UNSUPPORTED;
    if(!width || !height || width>INT32_MAX || height>INT32_MAX)return PW_ERR_PRECONDITION;
    PwGdiDc *destination=find_dc(gdi,destination_handle);if(!destination)return PW_ERR_NOT_FOUND;
    PwGdiSurface *dst;int status=dc_surface(gdi,destination,&dst);
    if(status!=PW_OK)return status;
    PwGdiSurface *src=NULL;
    if(rop==PW_GDI_ROP_SRCCOPY) {
        PwGdiDc *source=find_dc(gdi,source_handle);if(!source)return PW_ERR_NOT_FOUND;
        if((status=dc_surface(gdi,source,&src))!=PW_OK)return status;
    }
    int64_t dx0=x,dy0=y,dx1=(int64_t)x+width,dy1=(int64_t)y+height;
    int64_t sx0=source_x,sy0=source_y;
    if(dx0<0){if(src)sx0-=dx0;dx0=0;}
    if(dy0<0){if(src)sy0-=dy0;dy0=0;}
    if(dx1>dst->width)dx1=dst->width;
    if(dy1>dst->height)dy1=dst->height;
    if(src) {
        if(sx0<0){dx0-=sx0;sx0=0;}
        if(sy0<0){dy0-=sy0;sy0=0;}
        int64_t source_right=sx0+(dx1-dx0),source_bottom=sy0+(dy1-dy0);
        if(source_right>src->width)dx1-=source_right-src->width;
        if(source_bottom>src->height)dy1-=source_bottom-src->height;
    }
    if(dx0>=dx1 || dy0>=dy1)return PW_OK;
    x=(int32_t)dx0;y=(int32_t)dy0;source_x=(int32_t)sx0;source_y=(int32_t)sy0;
    width=(uint32_t)(dx1-dx0);height=(uint32_t)(dy1-dy0);
    uint8_t *dst_base=gdi->pixels+dst->offset;
    if(rop==PW_GDI_ROP_BLACKNESS) {
        for(uint32_t row=0;row<height;row++)
            memset(dst_base+(uint32_t)(y+(int32_t)row)*dst->stride+(uint32_t)x*4,0,width*4);
        return PW_OK;
    }
    uint8_t *src_base=gdi->pixels+src->offset;uint32_t row_bytes=width*4;
    if(src==dst && y>source_y) {
        for(uint32_t row=height;row>0;row--)
            memmove(dst_base+(uint32_t)(y+(int32_t)row-1)*dst->stride+(uint32_t)x*4,
                    src_base+(uint32_t)(source_y+(int32_t)row-1)*src->stride+(uint32_t)source_x*4,
                    row_bytes);
    } else {
        for(uint32_t row=0;row<height;row++)
            memmove(dst_base+(uint32_t)(y+(int32_t)row)*dst->stride+(uint32_t)x*4,
                    src_base+(uint32_t)(source_y+(int32_t)row)*src->stride+(uint32_t)source_x*4,
                    row_bytes);
    }
    return PW_OK;
}
int pw_gdi_stretch_dibits(PwGdi *gdi,uint32_t destination_handle,
                          int32_t x,int32_t y,int32_t width,int32_t height,
                          int32_t source_x,int32_t source_y,
                          int32_t source_width,int32_t source_height,
                          const uint8_t *bits,uint32_t bits_bytes,
                          const uint8_t *info,uint32_t info_bytes,
                          uint32_t usage,uint32_t rop,int32_t *scan_lines)
{
    if(!gdi || !bits || !info || !scan_lines)return PW_ERR_PRECONDITION;
    *scan_lines=0;
    if(info_bytes<40 || read32(info)<40 || read32(info)>info_bytes)return PW_ERR_TRUNCATED;
    int32_t dib_width=(int32_t)read32(info+4),dib_height=(int32_t)read32(info+8);
    uint16_t planes=read16(info+12),bpp=read16(info+14);
    uint32_t compression=read32(info+16),colors=read32(info+32);
    if(dib_width<=0 || !dib_height || dib_height==INT32_MIN || planes!=1 || compression!=0 ||
       (bpp!=8 && bpp!=24 && bpp!=32) || usage>1 || (usage && bpp!=8) ||
       rop!=PW_GDI_ROP_SRCCOPY)
        return PW_ERR_UNSUPPORTED;
    if(width<=0 || height<=0 || source_width<=0 || source_height<=0)
        return PW_ERR_PRECONDITION;
    uint32_t rows=dib_height<0?(uint32_t)-dib_height:(uint32_t)dib_height;
    if(source_x<0 || source_y<0 || (uint64_t)(uint32_t)source_x+(uint32_t)source_width>(uint32_t)dib_width ||
       (uint64_t)(uint32_t)source_y+(uint32_t)source_height>rows)return PW_ERR_PRECONDITION;
    uint64_t stride64=((uint64_t)(uint32_t)dib_width*bpp+31)/32*4;
    uint64_t required=stride64*rows;
    if(stride64>UINT32_MAX || required>bits_bytes)return PW_ERR_TRUNCATED;
    PwGdiDc *destination=find_dc(gdi,destination_handle);if(!destination)return PW_ERR_NOT_FOUND;
    PwGdiPalette *logical_palette=usage?find_palette(gdi,destination->selected_palette):NULL;
    if(usage && !logical_palette)return PW_ERR_STATE;
    uint32_t header=read32(info),palette_colors=0,palette_entry_bytes=usage?2:4;
    if(bpp==8) {
        palette_colors=colors?colors:256;
        if(palette_colors>256 ||
           (uint64_t)header+(uint64_t)palette_colors*palette_entry_bytes>info_bytes)
            return PW_ERR_TRUNCATED;
    }
    PwGdiSurface *dst;int status=dc_surface(gdi,destination,&dst);if(status!=PW_OK)return status;
    gdi->stretch_calls++;
    gdi->stretch_owner=destination->owner_window;
    gdi->stretch_bits=(uint32_t)(uintptr_t)bits;gdi->stretch_info=(uint32_t)(uintptr_t)info;
    gdi->stretch_dib_width=(uint32_t)dib_width;gdi->stretch_dib_height=rows;
    gdi->stretch_x=x;gdi->stretch_y=y;gdi->stretch_width=width;gdi->stretch_height=height;
    gdi->stretch_source_x=source_x;gdi->stretch_source_y=source_y;
    gdi->stretch_source_width=source_width;gdi->stretch_source_height=source_height;
    int64_t dx0=x,dy0=y,dx1=(int64_t)x+width,dy1=(int64_t)y+height;
    if(dx0<0)dx0=0;
    if(dy0<0)dy0=0;
    if(dx1>dst->width)dx1=dst->width;
    if(dy1>dst->height)dy1=dst->height;
    if(dx0<dx1 && dy0<dy1) {
        uint8_t *destination_pixels=gdi->pixels+dst->offset;
        for(int64_t dy=dy0;dy<dy1;dy++) {
            uint32_t relative_y=(uint32_t)(dy-y);
            uint32_t source_row_index=(uint32_t)((uint64_t)relative_y*(uint32_t)source_height/
                                                 (uint32_t)height);
            /* StretchDIBits expresses the Y origin of a bottom-up DIB from
             * the lower-left corner.  The first destination scanline is the
             * upper scanline of that source rectangle, not rows-1-source_y.
             * The distinction disappears for a whole-image blit, which is
             * why the old formula passed the splash test but vertically
             * mirrored subrect selection in Pinball's text panels. */
            uint32_t storage_y=dib_height>0?
                (uint32_t)source_y+(uint32_t)source_height-1-source_row_index:
                (uint32_t)source_y+source_row_index;
            const uint8_t *source_row=bits+(uint64_t)storage_y*(uint32_t)stride64;
            uint8_t *destination_row=destination_pixels+(uint32_t)dy*dst->stride;
            for(int64_t dx=dx0;dx<dx1;dx++) {
                uint32_t relative_x=(uint32_t)(dx-x);
                uint32_t sx=(uint32_t)source_x+(uint32_t)((uint64_t)relative_x*(uint32_t)source_width/(uint32_t)width);
                uint8_t *out=destination_row+(uint32_t)dx*4;
                if(bpp==8) {
                    uint32_t index=source_row[sx];if(index>=palette_colors)return PW_ERR_MALFORMED;
                    if(usage) {
                        uint32_t logical_index=read16(info+header+index*2);
                        if(logical_index>=logical_palette->count)return PW_ERR_MALFORMED;
                        const uint8_t *color=logical_palette->entries[logical_index];
                        out[0]=color[2];out[1]=color[1];out[2]=color[0];out[3]=255;
                    } else {
                        const uint8_t *color=info+header+index*4;
                        out[0]=color[0];out[1]=color[1];out[2]=color[2];out[3]=255;
                    }
                } else {
                    const uint8_t *pixel=source_row+(uint64_t)sx*(bpp/8);
                    out[0]=pixel[0];out[1]=pixel[1];out[2]=pixel[2];out[3]=bpp==32?pixel[3]:255;
                }
            }
        }
    }
    *scan_lines=source_height;return PW_OK;
}
int pw_gdi_counts(const PwGdi *gdi,PwGdiCounts *counts)
{
    if(!gdi || !counts)return PW_ERR_PRECONDITION;
    *counts=(PwGdiCounts){0};
    for(uint32_t i=0;i<gdi->dc_capacity;i++)if(gdi->dcs[i].used) {
        counts->dcs++;if(gdi->dcs[i].kind==PW_GDI_WINDOW_DC)counts->window_dcs++;
        else if(gdi->dcs[i].kind==PW_GDI_MEMORY_DC)counts->memory_dcs++;
    }
    for(uint32_t i=0;i<gdi->surface_capacity;i++)if(gdi->surfaces[i].used) {
        counts->surfaces++;counts->pixel_bytes+=gdi->surfaces[i].bytes;
        if(gdi->surfaces[i].kind==PW_GDI_TARGET_SURFACE)counts->target_surfaces++;
        else if(gdi->surfaces[i].kind==PW_GDI_BITMAP)counts->bitmaps++;
    }
    for(uint32_t i=0;i<PW_GDI_PALETTE_CAPACITY;i++)if(gdi->palettes[i].used)counts->palettes++;
    return PW_OK;
}
int pw_gdi_set_system_palette_use(PwGdi *gdi,uint32_t dc,uint32_t use,uint32_t *previous)
{
    if(!gdi || !previous || (use!=1 && use!=2))return PW_ERR_PRECONDITION;
    if(!find_dc(gdi,dc))return PW_ERR_NOT_FOUND;
    *previous=gdi->system_palette_use;gdi->system_palette_use=use;return PW_OK;
}
int pw_gdi_get_system_palette_entries(PwGdi *gdi,uint32_t dc,uint32_t start,uint32_t count,
                                      uint8_t entries[][4],uint32_t *copied)
{
    if(!gdi || !copied || start>256 || count>256-start || (count && !entries))
        return PW_ERR_PRECONDITION;
    PwGdiDc *context=find_dc(gdi,dc);if(!context)return PW_ERR_NOT_FOUND;
    PwGdiPalette *palette=find_palette(gdi,context->selected_palette);
    for(uint32_t i=0;i<count;i++) {
        uint32_t index=start+i;
        if(palette && index<palette->count)memcpy(entries[i],palette->entries[index],4);
        else {
            uint8_t level=(uint8_t)index;
            entries[i][0]=level;entries[i][1]=level;entries[i][2]=level;entries[i][3]=0;
        }
    }
    *copied=count;return PW_OK;
}
int pw_gdi_validate(const PwGdi *gdi)
{
    if(!gdi || !gdi->dcs || !gdi->surfaces || !gdi->pixels || !gdi->dc_capacity ||
       !gdi->surface_capacity || !gdi->pixel_capacity)return PW_ERR_PRECONDITION;
    for(uint32_t i=0;i<gdi->surface_capacity;i++) {
        const PwGdiSurface *a=&gdi->surfaces[i];if(!a->used)continue;
        if(!a->width || !a->height || !a->stride || !a->bytes ||
           (uint64_t)a->offset+a->bytes>gdi->pixel_capacity)return PW_ERR_STATE;
        uint32_t selected=0;
        for(uint32_t j=0;j<gdi->dc_capacity;j++)
            if(gdi->dcs[j].used && gdi->dcs[j].kind==PW_GDI_MEMORY_DC &&
               gdi->dcs[j].surface==i && gdi->dcs[j].selected_bitmap==a->handle)selected++;
        if(a->kind==PW_GDI_BITMAP && selected!=a->selected_by)return PW_ERR_STATE;
        for(uint32_t j=i+1;j<gdi->surface_capacity;j++) {
            const PwGdiSurface *b=&gdi->surfaces[j];if(!b->used)continue;
            if(a->offset<(uint64_t)b->offset+b->bytes && b->offset<(uint64_t)a->offset+a->bytes)
                return PW_ERR_STATE;
        }
    }
    for(uint32_t i=0;i<gdi->dc_capacity;i++) {
        const PwGdiDc *dc=&gdi->dcs[i];if(!dc->used)continue;
        if(dc->kind==PW_GDI_WINDOW_DC) {
            if(dc->surface>=gdi->surface_capacity || !gdi->surfaces[dc->surface].used ||
               gdi->surfaces[dc->surface].kind!=PW_GDI_TARGET_SURFACE ||
               gdi->surfaces[dc->surface].target!=dc->owner_window)return PW_ERR_STATE;
        } else if(dc->kind==PW_GDI_MEMORY_DC) {
            if(dc->selected_bitmap==PW_GDI_STOCK_BITMAP) {
                if(dc->surface!=PW_GDI_NO_SURFACE)return PW_ERR_STATE;
            } else if(dc->surface>=gdi->surface_capacity || !gdi->surfaces[dc->surface].used ||
                      gdi->surfaces[dc->surface].handle!=dc->selected_bitmap)return PW_ERR_STATE;
        } else return PW_ERR_STATE;
        if(dc->selected_palette && !find_palette((PwGdi *)gdi,dc->selected_palette))
            return PW_ERR_STATE;
    }
    for(uint32_t i=0;i<PW_GDI_PALETTE_CAPACITY;i++)if(gdi->palettes[i].used) {
        const PwGdiPalette *palette=&gdi->palettes[i];uint32_t selected=0;
        if(palette->version!=0x300 || !palette->count || palette->count>PW_GDI_PALETTE_ENTRIES)
            return PW_ERR_STATE;
        for(uint32_t j=0;j<gdi->dc_capacity;j++)
            if(gdi->dcs[j].used && gdi->dcs[j].selected_palette==palette->handle)selected++;
        if(selected!=palette->selected_by)return PW_ERR_STATE;
    }
    return PW_OK;
}
int pw_gdi_reset(PwGdi *gdi)
{
    if(!gdi || !gdi->dcs || !gdi->surfaces || !gdi->pixels)return PW_ERR_PRECONDITION;
    memset(gdi->dcs,0,sizeof(*gdi->dcs)*gdi->dc_capacity);
    memset(gdi->surfaces,0,sizeof(*gdi->surfaces)*gdi->surface_capacity);
    memset(gdi->palettes,0,sizeof(gdi->palettes));
    memset(gdi->pixels,0,gdi->pixel_capacity);gdi->next_handle=PW_GDI_HANDLE_FIRST;
    gdi->system_palette_use=1;
    return PW_OK;
}
