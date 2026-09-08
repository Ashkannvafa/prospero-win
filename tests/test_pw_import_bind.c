/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pe_fixture.h"
#include "../src/pw_import_bind.h"
#include "../src/pw_vm_posix.h"
#include <assert.h>
#include <string.h>
static uint8_t file[65536],before[65536];
static PwImportBindWorkspace work;
typedef struct Context { unsigned calls,mode; } Context;
static int resolver(void *opaque,const char *dll,const PeImportSymbol *symbol,PwImportTarget *out)
{
    Context *c=opaque;c->calls++;
    assert(strcmp(dll,"test.dll")==0);
    if(c->mode==1 && c->calls==2)return PW_ERR_NOT_FOUND;
    if(c->mode==2){out->address=0x100000000ull;out->kind=PW_IMPORT_FUNCTION;return PW_OK;}
    if(c->mode==3){out->address=0;out->kind=PW_IMPORT_FUNCTION;return PW_OK;}
    if(c->mode==4){out->address=0x3000000;out->kind=0;return PW_OK;}
    out->kind=!symbol->by_ordinal && strcmp(symbol->name,"Data")==0?PW_IMPORT_DATA:PW_IMPORT_FUNCTION;
    out->address=out->kind==PW_IMPORT_DATA?0x03000000:0xf0000000+c->calls*16;
    return PW_OK;
}
int main(void)
{
    static const uint8_t code[]={0xc3};
    PeFixtureSpec spec={0};spec.image_base=0x02000000;spec.section_count=1;spec.entry_point=0x1000;
    spec.sections[0].name=".text";spec.sections[0].data=code;spec.sections[0].data_bytes=1;
    spec.sections[0].characteristics=PE_SCN_CNT_CODE|PE_SCN_MEM_READ|PE_SCN_MEM_EXECUTE;
    spec.import_count=1;spec.imports[0].dll="test.dll";
    spec.imports[0].names[0]="Function";spec.imports[0].names[1]="Data";spec.imports[0].ordinals[0]=42;
    size_t bytes=pe_fixture_build(file,sizeof(file),&spec);assert(bytes);
    PeImage image;PeLayout layout;PwMappedImage mapped;PwVmBackend vm;PwImportBindReport report;
    assert(pe_image_parse(&image,file,bytes)==PW_OK);
    assert(pe_layout_plan(&layout,&image)==PW_OK);
    assert(pw_vm_posix_backend(&vm)==PW_OK);
    assert(pw_map_image(&mapped,&image,&layout,&vm)==PW_OK);
    assert(mapped.image_bytes<=sizeof(before));memcpy(before,mapped.region.write_base,mapped.image_bytes);
    Context denied={0};
    image.directories[PE_DIR_DELAY_IMPORT].size=1;
    assert(pw_import_bind32(&image,&mapped,resolver,&denied,&work,&report)==PW_ERR_UNSUPPORTED);
    image.directories[PE_DIR_DELAY_IMPORT].size=0;
    assert(denied.calls==0 && memcmp(before,mapped.region.write_base,mapped.image_bytes)==0);
    for(unsigned mode=1;mode<=4;mode++) {
        Context c={0,mode};
        int expected=mode==1?PW_ERR_NOT_FOUND:PW_ERR_PRECONDITION;
        assert(pw_import_bind32(&image,&mapped,resolver,&c,&work,&report)==expected);
        assert(report.total==0 && memcmp(before,mapped.region.write_base,mapped.image_bytes)==0);
    }
    Context context={0};
    assert(pw_import_bind32(&image,&mapped,resolver,&context,&work,&report)==PW_OK);
    assert(report.total==3 && report.functions==2 && report.data==1);
    for(unsigned i=0;i<3;i++) {
        uint32_t value;memcpy(&value,work.writes[i].slot,4);
        assert(value==work.writes[i].value);
    }
    assert(pw_map_finalize_protections(&mapped,&layout,&vm)==PW_OK);
    context.calls=0;
    assert(pw_import_bind32(&image,&mapped,resolver,&context,&work,&report)==PW_ERR_STATE);
    assert(context.calls==0);
    assert(pw_map_release(&mapped,&vm)==PW_OK);
    /* Two descriptors overlapping the same IAT must not overwrite each
     * other, even though each descriptor parses independently. */
    spec.import_count=2;spec.imports[1].dll="test.dll";spec.imports[1].names[0]="Extra";
    bytes=pe_fixture_build(file,sizeof(file),&spec);assert(bytes);
    assert(pe_image_parse(&image,file,bytes)==PW_OK);
    assert(pe_import_parse(&work.table,&image)==PW_OK);
    size_t descriptor;
    assert(pe_image_file_offset(&image,image.directories[PE_DIR_IMPORT].virtual_address,40,&descriptor)==PW_OK);
    uint32_t duplicate=work.table.modules[0].address_table_rva;
    memcpy(file+descriptor+20+16,&duplicate,4);
    assert(pe_layout_plan(&layout,&image)==PW_OK);
    assert(pw_map_image(&mapped,&image,&layout,&vm)==PW_OK);
    memcpy(before,mapped.region.write_base,mapped.image_bytes);
    context.calls=0;
    assert(pw_import_bind32(&image,&mapped,resolver,&context,&work,&report)==PW_ERR_MALFORMED);
    assert(report.total==0 && memcmp(before,mapped.region.write_base,mapped.image_bytes)==0);
    assert(pw_map_release(&mapped,&vm)==PW_OK);
    return 0;
}
