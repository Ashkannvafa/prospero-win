/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pw_ini.h"
#include <assert.h>
#include <string.h>
int main(void)
{
    static const char ini[]="; header\r\n[general]\r\nShowDevices=0\r\n"
        "WaveOutDevice = -1 ; mapper\n[WinNT:default]\nWaveBlocks=3\nHex=0x2a\nBad=12x\n";
    uint32_t value=99;
    assert(pw_ini_get_int((const uint8_t *)ini,strlen(ini),"GENERAL","showdevices",7,&value)==PW_OK&&value==0);
    assert(pw_ini_get_int((const uint8_t *)ini,strlen(ini),"general","WaveOutDevice",7,&value)==PW_OK&&value==UINT32_MAX);
    assert(pw_ini_get_int((const uint8_t *)ini,strlen(ini),"WinNT:default","WaveBlocks",7,&value)==PW_OK&&value==3);
    assert(pw_ini_get_int((const uint8_t *)ini,strlen(ini),"WinNT:default","Hex",7,&value)==PW_OK&&value==42);
    assert(pw_ini_get_int((const uint8_t *)ini,strlen(ini),"WinNT:default","Bad",7,&value)==PW_OK&&value==7);
    assert(pw_ini_get_int((const uint8_t *)ini,strlen(ini),"missing","key",11,&value)==PW_OK&&value==11);
    assert(pw_ini_get_int(NULL,0,"a","b",0,&value)==PW_ERR_PRECONDITION);
    return 0;
}
