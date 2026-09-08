/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_import_bind.h"
#include <string.h>
int pw_import_bind32(const PeImage *image,PwMappedImage *mapped,
                     PwImportResolver resolve,void *context,
                     PwImportBindWorkspace *work,PwImportBindReport *report)
{
    if(!image || !mapped || !resolve || !work || !report)return PW_ERR_PRECONDITION;
    memset(report,0,sizeof(*report));
    if(image->machine!=PE_MACHINE_I386 || image->optional_magic!=PE_OPT_MAGIC_PE32 ||
       mapped->address_bits!=32)return PW_ERR_UNSUPPORTED;
    if(mapped->protections_applied || !mapped->region.write_base ||
       mapped->image_bytes!=image->size_of_image)return PW_ERR_STATE;
    if(image->directories[PE_DIR_DELAY_IMPORT].size)return PW_ERR_UNSUPPORTED;
    int result=pe_import_parse(&work->table,image);
    if(result!=PW_OK)return result;
    if(work->table.symbol_count>PW_IMPORT_BIND_CAPACITY)return PW_ERR_LIMIT;
    unsigned total=0;
    for(unsigned i=0;i<work->table.module_count;i++) {
        const PeImportModule *module=&work->table.modules[i];uint32_t count=0;
        result=pe_import_enumerate(image,module,work->symbols,PW_IMPORT_BIND_CAPACITY,&count);
        if(result!=PW_OK)return result;
        for(unsigned j=0;j<count;j++) {
            if(total==PW_IMPORT_BIND_CAPACITY)return PW_ERR_LIMIT;
            const PeImportSymbol *symbol=&work->symbols[j];
            void *slot=pw_map_writable(mapped,symbol->thunk_rva,4);
            if(!slot)return PW_ERR_MALFORMED;
            for(unsigned k=0;k<total;k++)
                if((uint64_t)symbol->thunk_rva<(uint64_t)work->writes[k].rva+4 &&
                   (uint64_t)work->writes[k].rva<(uint64_t)symbol->thunk_rva+4)
                    return PW_ERR_MALFORMED;
            PwImportTarget target={0};
            result=resolve(context,module->name,symbol,&target);
            if(result!=PW_OK)return result;
            if(!target.address || target.address>UINT32_MAX ||
               (target.kind!=PW_IMPORT_FUNCTION && target.kind!=PW_IMPORT_DATA))
                return PW_ERR_PRECONDITION;
            work->writes[total++]=(PwImportWrite){slot,symbol->thunk_rva,(uint32_t)target.address,target.kind};
        }
    }
    PwImportBindReport finished={0};
    for(unsigned i=0;i<total;i++) {
        const PwImportWrite *write=&work->writes[i];
        memcpy(write->slot,&write->value,4);
        if(write->kind==PW_IMPORT_FUNCTION)finished.functions++;else finished.data++;
    }
    finished.total=total;*report=finished;
    return PW_OK;
}
