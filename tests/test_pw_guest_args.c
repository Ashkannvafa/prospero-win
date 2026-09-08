/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pw_guest_args.h"
#include "../include/prospero_win.h"
#include <assert.h>
#include <string.h>
static void check(const char *line,const char *const *expected,unsigned count)
{
    unsigned char bytes[4096];PwGuestArgs args;
    const char *env[]={"DEMO=one","EMPTY="};
    assert(pw_guest_args_build(line,env,2,0x10000,bytes,sizeof(bytes),&args)==PW_OK && args.argc==count);
    for(unsigned i=0;i<count+1;i++) {
        uint32_t ptr;memcpy(&ptr,bytes+i*4,4);
        if(i==count)assert(!ptr);
        else {assert(ptr>=0x10000 && ptr<0x10000+args.bytes);assert(!strcmp((char *)bytes+(ptr-0x10000),expected[i]));}
    }
    for(unsigned i=0;i<3;i++) {
        uint32_t ptr;memcpy(&ptr,bytes+(args.envp-0x10000)+i*4,4);
        if(i==2)assert(!ptr);else assert(!strcmp((char *)bytes+(ptr-0x10000),env[i]));
    }
}
int main(void)
{
    const char *a[]={"C:\\Games Folder\\demo.exe","one","two three",""};
    check("\"C:\\Games Folder\\demo.exe\" one \"two three\" \"\"",a,4);
    const char *b[]={"demo","pre spaced post","a\"b","tail\\"};
    check("demo pre\" spaced \"post a\\\"b tail\\",b,4);
    const char *c[]={"demo","a\"b","open text"};
    check("demo \"a\"\"b\" \"open text",c,3);
    const char *d[]={""};check("",d,1);
    unsigned char bytes[32],before[32];memset(bytes,0xaa,sizeof(bytes));memcpy(before,bytes,sizeof(bytes));
    PwGuestArgs args={.argc=99},saved=args;
    assert(pw_guest_args_build("long.exe some arguments here",NULL,0,0x10000,bytes,1,&args)==PW_ERR_LIMIT);
    assert(!memcmp(bytes,before,sizeof(bytes)) && !memcmp(&args,&saved,sizeof(args)));
    assert(pw_guest_args_build("demo",NULL,0,0xfffffff8,bytes,sizeof(bytes),&args)==PW_ERR_LIMIT);
    assert(!memcmp(bytes,before,sizeof(bytes)));
    char many[300];for(unsigned i=0;i<sizeof(many)-1;i++)many[i]=i&1?' ':'a';many[299]=0;
    assert(pw_guest_args_build(many,NULL,0,0x10000,bytes,sizeof(bytes),&args)==PW_ERR_LIMIT);
    return 0;
}
