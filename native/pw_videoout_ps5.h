/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_VIDEOOUT_PS5_H
#define PW_VIDEOOUT_PS5_H
#include "../src/pw_gdi.h"
#include "pw_agc_ps5.h"
#include <stdint.h>
typedef struct PwVideoOutPs5 {
    void *memory;int64_t physical;size_t bytes,frame_bytes;
    PwAgcPs5 agc;
    int handle;unsigned index,opened,allocated,mapped,buffers_registered;uint64_t flips;
    int unregister_rc,close_rc,munmap_rc,release_rc,agc_close_rc;
} PwVideoOutPs5;
int pw_videoout_ps5_open(PwVideoOutPs5 *);
int pw_videoout_ps5_close(PwVideoOutPs5 *);
int pw_videoout_ps5_present(PwVideoOutPs5 *,const PwGdiTargetView *);
#endif
