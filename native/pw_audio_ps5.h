/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_AUDIO_PS5_H
#define PW_AUDIO_PS5_H
#include "../src/pw_win32.h"
#include <stdint.h>

enum { PW_AUDIO_PS5_RATE=48000, PW_AUDIO_PS5_GRAIN=256,
       PW_AUDIO_PS5_CHANNELS=2 };

typedef struct PwAudioPs5Ops {
    int (*init)(void);
    int (*open)(int user_id,int type,int index,uint32_t grain,
                uint32_t rate,uint32_t format);
    int (*volume)(int handle,int flags,const int32_t *volumes);
    int (*output)(int handle,const void *samples);
    int (*close)(int handle);
} PwAudioPs5Ops;

typedef struct PwAudioPs5 {
    PwAudioPs5Ops ops;
    int handle;
    uint32_t input_rate,phase,accum_frames;
    uint16_t input_channels,input_bits;
    int16_t accum[PW_AUDIO_PS5_GRAIN*PW_AUDIO_PS5_CHANNELS];
    uint64_t input_bytes,output_frames,blocks;
    uint32_t input_hash;
    unsigned opened;
} PwAudioPs5;

int pw_audio_ps5_init(PwAudioPs5 *,const PwAudioPs5Ops *);
int pw_audio_ps5_open(void *,uint32_t,uint16_t,uint16_t);
int pw_audio_ps5_submit(void *,const void *,uint32_t);
int pw_audio_ps5_control(void *,PwAudioControl);
int pw_audio_ps5_platform_ops(PwAudioPs5Ops *);

#endif
