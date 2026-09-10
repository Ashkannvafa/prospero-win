/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_audio_ps5.h"
#include <string.h>

enum { PW_AUDIO_PS5_USER_SYSTEM=0xff, PW_AUDIO_PS5_PORT_MAIN=0,
       PW_AUDIO_PS5_PORT_INDEX=0, PW_AUDIO_PS5_FORMAT_S16_STEREO=1,
       PW_AUDIO_PS5_VOLUME_FLAGS=3, PW_AUDIO_PS5_VOLUME_0DB=0x8000 };

#ifndef PW_AUDIO_PS5_HOST_TEST
extern int sceAudioOutInit(void);
extern int sceAudioOutOpen(int,int,int,uint32_t,uint32_t,uint32_t);
extern int sceAudioOutSetVolume(int,int,const int32_t *);
extern int sceAudioOutOutput(int,const void *);
extern int sceAudioOutClose(int);

static int platform_init(void){return sceAudioOutInit();}
static int platform_open(int u,int t,int i,uint32_t g,uint32_t r,uint32_t f)
{return sceAudioOutOpen(u,t,i,g,r,f);}
static int platform_volume(int h,int f,const int32_t *v)
{return sceAudioOutSetVolume(h,f,v);}
static int platform_output(int h,const void *p){return sceAudioOutOutput(h,p);}
static int platform_close(int h){return sceAudioOutClose(h);}
#endif

int pw_audio_ps5_platform_ops(PwAudioPs5Ops *ops)
{
    if(!ops)return PW_ERR_PRECONDITION;
#ifdef PW_AUDIO_PS5_HOST_TEST
    memset(ops,0,sizeof(*ops));return PW_ERR_UNSUPPORTED;
#else
    *ops=(PwAudioPs5Ops){platform_init,platform_open,platform_volume,
                         platform_output,platform_close};
    return PW_OK;
#endif
}
int pw_audio_ps5_init(PwAudioPs5 *audio,const PwAudioPs5Ops *ops)
{
    if(!audio || !ops || !ops->init || !ops->open || !ops->volume ||
       !ops->output || !ops->close)return PW_ERR_PRECONDITION;
    memset(audio,0,sizeof(*audio));audio->ops=*ops;audio->handle=-1;return PW_OK;
}
static int emit(PwAudioPs5 *audio)
{
    int result=audio->ops.output(audio->handle,audio->accum);
    if(result<0)return PW_ERR_STATE;
    audio->blocks++;audio->output_frames+=PW_AUDIO_PS5_GRAIN;
    audio->accum_frames=0;return PW_OK;
}
int pw_audio_ps5_open(void *opaque,uint32_t rate,uint16_t channels,uint16_t bits)
{
    PwAudioPs5 *audio=opaque;int32_t volumes[8];
    if(!audio || !rate || (channels!=1 && channels!=2) ||
       (bits!=8 && bits!=16))return PW_ERR_PRECONDITION;
    if(audio->opened)return PW_ERR_STATE;
    int result=audio->ops.init();if(result<0)return PW_ERR_STATE;
    result=audio->ops.open(PW_AUDIO_PS5_USER_SYSTEM,PW_AUDIO_PS5_PORT_MAIN,
        PW_AUDIO_PS5_PORT_INDEX,PW_AUDIO_PS5_GRAIN,PW_AUDIO_PS5_RATE,
        PW_AUDIO_PS5_FORMAT_S16_STEREO);
    if(result<0)return PW_ERR_STATE;
    for(unsigned i=0;i<8;i++)volumes[i]=PW_AUDIO_PS5_VOLUME_0DB;
    if(audio->ops.volume(result,PW_AUDIO_PS5_VOLUME_FLAGS,volumes)<0) {
        (void)audio->ops.close(result);return PW_ERR_STATE;
    }
    audio->handle=result;audio->input_rate=rate;audio->input_channels=channels;
    audio->input_bits=bits;audio->phase=0;audio->accum_frames=0;audio->opened=1;
    return PW_OK;
}
static int16_t sample(const uint8_t *input,uint16_t bits)
{
    if(bits==8)return (int16_t)(((int)input[0]-128)<<8);
    return (int16_t)((uint16_t)input[0]|(uint16_t)input[1]<<8);
}
int pw_audio_ps5_submit(void *opaque,const void *pcm,uint32_t bytes)
{
    PwAudioPs5 *audio=opaque;const uint8_t *input=pcm;
    if(!audio || !audio->opened || !input || !bytes)return PW_ERR_PRECONDITION;
    uint32_t frame_bytes=(uint32_t)audio->input_channels*(audio->input_bits/8u);
    if(bytes%frame_bytes)return PW_ERR_PRECONDITION;
    uint32_t hash=audio->input_hash?audio->input_hash:2166136261u;
    for(uint32_t i=0;i<bytes;i++){hash^=input[i];hash*=16777619u;}
    for(uint32_t offset=0;offset<bytes;offset+=frame_bytes) {
        int16_t left=sample(input+offset,audio->input_bits);
        int16_t right=audio->input_channels==2?
            sample(input+offset+audio->input_bits/8u,audio->input_bits):left;
        audio->phase+=PW_AUDIO_PS5_RATE;
        while(audio->phase>=audio->input_rate) {
            audio->phase-=audio->input_rate;
            audio->accum[audio->accum_frames*2]=left;
            audio->accum[audio->accum_frames*2+1]=right;
            audio->accum_frames++;
            if(audio->accum_frames==PW_AUDIO_PS5_GRAIN) {
                int status=emit(audio);if(status!=PW_OK)return status;
            }
        }
    }
    audio->input_hash=hash;audio->input_bytes+=bytes;return PW_OK;
}
int pw_audio_ps5_control(void *opaque,PwAudioControl control)
{
    PwAudioPs5 *audio=opaque;if(!audio || !audio->opened)return PW_ERR_PRECONDITION;
    if(control==PW_AUDIO_PAUSE || control==PW_AUDIO_RESTART)return PW_OK;
    if(control==PW_AUDIO_RESET){audio->phase=0;audio->accum_frames=0;return PW_OK;}
    if(control!=PW_AUDIO_CLOSE)return PW_ERR_UNSUPPORTED;
    if(audio->accum_frames) {
        memset(audio->accum+audio->accum_frames*2,0,
               (PW_AUDIO_PS5_GRAIN-audio->accum_frames)*2*sizeof(int16_t));
        int status=emit(audio);if(status!=PW_OK)return status;
    }
    if(audio->ops.close(audio->handle)<0)return PW_ERR_STATE;
    audio->opened=0;audio->handle=-1;return PW_OK;
}
