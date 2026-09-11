/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_state_ps5.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef PW_STATE_PS5_HOST_TEST
static int platform_open(const char *path,int flags,int mode){return open(path,flags,mode);}
static int platform_close(int descriptor){return close(descriptor);}
static int platform_stat(const char *path,struct stat *value){return stat(path,value);}
static int platform_rename(const char *from,const char *to){return rename(from,to);}
static int platform_unlink(const char *path){return unlink(path);}
#else
extern int sceKernelOpen(const char *,int,int);
extern int sceKernelClose(int);
extern int sceKernelStat(const char *,struct stat *);
extern int sceKernelRename(const char *,const char *);
extern int sceKernelUnlink(const char *);
#define platform_open sceKernelOpen
#define platform_close sceKernelClose
#define platform_stat sceKernelStat
#define platform_rename sceKernelRename
#define platform_unlink sceKernelUnlink
#endif

static int read_all(int descriptor,uint8_t *buffer,uint32_t bytes)
{
    uint32_t done=0;while(done<bytes) {
        ssize_t result=read(descriptor,buffer+done,bytes-done);
        if(result>0){done+=(uint32_t)result;continue;}
        if(result<0 && errno==EINTR)continue;
        return PW_ERR_TRUNCATED;
    }
    return PW_OK;
}
static int write_all(int descriptor,const uint8_t *buffer,uint32_t bytes,
                     PwStatePs5Report *report)
{
    uint32_t done=0;while(done<bytes) {
        ssize_t result=write(descriptor,buffer+done,bytes-done);
        report->write_rc=(int)result;
        if(result>0){done+=(uint32_t)result;report->written_bytes=done;continue;}
        if(result<0 && errno==EINTR)continue;
        return PW_ERR_STATE;
    }
    return PW_OK;
}
int pw_state_ps5_load_registry(PwRegistry *registry,const char *path,uint8_t *buffer,
                               uint32_t capacity,uint32_t *loaded)
{
    if(!registry || !path || !*path || !buffer || !capacity || !loaded)
        return PW_ERR_PRECONDITION;
    *loaded=0;struct stat info;
    if(platform_stat(path,&info))return PW_OK; /* first run has no state */
    if(info.st_size<=0 || (uint64_t)info.st_size>capacity)return PW_ERR_MALFORMED;
    int descriptor=platform_open(path,O_RDONLY,0);if(descriptor<0)return PW_ERR_STATE;
    uint32_t bytes=(uint32_t)info.st_size;int status=read_all(descriptor,buffer,bytes);
    if(platform_close(descriptor) && status==PW_OK)status=PW_ERR_STATE;
    if(status==PW_OK)status=pw_registry_decode(registry,buffer,bytes);
    if(status==PW_OK)*loaded=bytes;
    return status;
}
int pw_state_ps5_save_registry(const PwRegistry *registry,const char *path,uint8_t *buffer,
                               uint32_t capacity,uint32_t *written)
{
    PwStatePs5Report report;
    return pw_state_ps5_save_registry_ex(registry,path,buffer,capacity,written,&report);
}
int pw_state_ps5_save_registry_ex(const PwRegistry *registry,const char *path,uint8_t *buffer,
                                  uint32_t capacity,uint32_t *written,PwStatePs5Report *report)
{
    if(!registry || !path || !*path || !buffer || !capacity || !written || !report)
        return PW_ERR_PRECONDITION;
    memset(report,0,sizeof(*report));
    *written=0;size_t length=strlen(path);if(length+5>=512)return PW_ERR_LIMIT;
    char temporary[512];memcpy(temporary,path,length);memcpy(temporary+length,".tmp",5);
    uint32_t bytes=0;int status=pw_registry_encode(registry,buffer,capacity,&bytes);
    if(status!=PW_OK)return status;
    report->encoded_bytes=bytes;
    int descriptor=platform_open(temporary,O_WRONLY|O_CREAT|O_TRUNC,0600);
    report->open_rc=descriptor;
    if(descriptor<0)return PW_ERR_STATE;
    status=write_all(descriptor,buffer,bytes,report);
    if(status==PW_OK && (report->fsync_rc=fsync(descriptor)))status=PW_ERR_STATE;
    report->close_rc=platform_close(descriptor);
    if(report->close_rc && status==PW_OK)status=PW_ERR_STATE;
    if(status==PW_OK) {
        report->rename_rc=platform_rename(temporary,path);
        if(report->rename_rc)status=PW_ERR_STATE;
    }
    if(status!=PW_OK){report->unlink_rc=platform_unlink(temporary);return status;}
    *written=bytes;return PW_OK;
}
