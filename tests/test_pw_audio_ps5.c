/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../native/pw_audio_ps5.h"
#include <assert.h>
#include <string.h>
static unsigned inits,opens,volumes,outputs,closes;static int16_t last[512];
static int op_init(void){inits++;return 0;}
static int op_open(int u,int t,int i,uint32_t g,uint32_t r,uint32_t f)
{assert(u==0xff&&t==0&&i==0&&g==256&&r==48000&&f==1);opens++;return 7;}
static int op_volume(int h,int flags,const int32_t *v)
{assert(h==7&&flags==3&&v[0]==0x8000&&v[7]==0x8000);volumes++;return 0;}
static int op_output(int h,const void *p)
{assert(h==7);memcpy(last,p,sizeof(last));outputs++;return 0;}
static int op_close(int h){assert(h==7);closes++;return 0;}
int main(void)
{
    PwAudioPs5 audio;PwAudioPs5Ops ops={op_init,op_open,op_volume,op_output,op_close};
    assert(pw_audio_ps5_init(&audio,&ops)==PW_OK);
    assert(pw_audio_ps5_open(&audio,11025,1,8)==PW_OK);
    uint8_t pcm[256];memset(pcm,255,sizeof(pcm));
    assert(pw_audio_ps5_submit(&audio,pcm,sizeof(pcm))==PW_OK);
    assert(outputs>=4 && last[0]==32512 && last[1]==32512);
    assert(audio.output_frames==outputs*256u && audio.input_bytes==256);
    assert(audio.input_hash==0x06a34ac5u);
    assert(pw_audio_ps5_control(&audio,PW_AUDIO_PAUSE)==PW_OK);
    assert(pw_audio_ps5_control(&audio,PW_AUDIO_RESTART)==PW_OK);
    assert(pw_audio_ps5_control(&audio,PW_AUDIO_CLOSE)==PW_OK);
    assert(inits==1&&opens==1&&volumes==1&&closes==1&&!audio.opened);
    return 0;
}
