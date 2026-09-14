/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The unix-call adapter: the frame the PE side leaves, and the services.
 *
 * `__wine_unix_call_dispatcher` is declared WINAPI (stdcall on i386), so a
 * guest that calls it through the exported data pointer leaves exactly:
 *
 *   [esp]     return PC
 *   [esp+4]   handle
 *   [esp+8]   code
 *   [esp+12]  args pointer
 *
 * read out of the guest stack by the dispatcher's own assembly
 * (dlls/ntdll/unix/signal_i386.c:2777-2845) before it calls
 * `*(handle + code*4)`. This unit parses that frame through the dispatcher's
 * validated accessor - never by dereferencing a guest pointer itself - and
 * implements the calls the pinned trace reaches.
 *
 * The handle is the gate's own opaque value bound to the pinned runtime, not
 * Wine's host address of `unix_call_funcs[]`: a guest that presents anything
 * else gets a classified refusal rather than a call into a table it named.
 */
#ifndef PROSPERO_WIN_PW_WINE_UNIXLIB_H
#define PROSPERO_WIN_PW_WINE_UNIXLIB_H

#include "pw_unix_call.h"
#include "pw_unixlib.h"

enum {
    /*
     * The frame the dispatcher reads, and the reason it is five slots and not
     * four: `unixlib_handle_t` is `UINT64` (include/wine/unixlib.h:30), so the
     * first argument occupies two dwords even in the i386 build. The pinned
     * assembly is the authority - it reads `handle` from `[esp]`, `code` from
     * `[esp+8]` and `args` from `[esp+12]`, skipping exactly the handle's high
     * half (dlls/ntdll/unix/signal_i386.c:2798-2812) - and the exact PE call
     * site loads the handle with two adjacent `mov` reads for the same reason.
     *
     *   [esp]     return PC
     *   [esp+4]   handle low
     *   [esp+8]   handle high
     *   [esp+12]  code
     *   [esp+16]  args
     *
     * The callee then cleans the four argument dwords plus the return PC,
     * which is why the resume adds twenty bytes.
     */
    PW_WINE_UNIXLIB_FRAME_BYTES = 20,
    PW_WINE_UNIXLIB_HANDLE_BYTES = 8,
    PW_WINE_UNIXLIB_HANDLE_OFFSET = 4,
    PW_WINE_UNIXLIB_HANDLE_HIGH_OFFSET = 8,
    PW_WINE_UNIXLIB_CODE_OFFSET = 12,
    PW_WINE_UNIXLIB_ARGS_OFFSET = 16,
    /* One debug write is bounded: the sink is a transcript, not a channel for
     * an unbounded guest buffer. */
    PW_WINE_UNIXLIB_MAX_DEBUG_BYTES = 4096,
    /*
     * Where the published boundary lives inside the gate-owned thread block
     * (the TEB's page). The page belongs to the run, the offset is past every
     * documented TEB field, and the two bytes there are `ud2`: the run loop
     * recognises the boundary before executing anything, and if it ever did
     * execute, it would stop as an unsupported instruction instead of running
     * whatever happened to be there.
     */
    PW_WINE_UNIXLIB_BOUNDARY_OFFSET = 0x800,
};

/*
 * The host side of `unix_wine_dbg_write`. Wine's Unix side does
 * `write(2, params->str, params->len)`; the portable core does not write to a
 * host stream itself, so a run injects this. The gate records the length and
 * the status as evidence, never the guest's text, which can contain anything.
 */
typedef struct PwWineDebugSink {
    void *context;
    /* Returns 0 for a delivered write, non-zero for a refused one. */
    int (*write)(void *context, const void *bytes, uint32_t length);
} PwWineDebugSink;

typedef struct PwWineUnixlibFrame {
    uint32_t return_pc;
    uint32_t handle;                /* the low half of the 64-bit handle */
    uint32_t handle_high;
    uint32_t code;
    uint32_t args;
} PwWineUnixlibFrame;

/*
 * What one call did. The values are distinct on purpose: an unknown handle, a
 * code outside the pinned table, an unreadable frame, a service that failed and
 * a call that is deliberately unimplemented are five different facts, and the
 * evidence has to be able to tell them apart instead of collapsing them into a
 * failure.
 */
typedef enum PwWineUnixlibStatus {
    PW_WINE_UNIXLIB_OK = 0,
    PW_WINE_UNIXLIB_MALFORMED = 1,
    PW_WINE_UNIXLIB_UNKNOWN_HANDLE = 2,
    PW_WINE_UNIXLIB_UNKNOWN_CODE = 3,
    PW_WINE_UNIXLIB_SERVICE_FAILED = 4,
    PW_WINE_UNIXLIB_UNIMPLEMENTED = 5,
} PwWineUnixlibStatus;

const char *pw_wine_unixlib_status_name(PwWineUnixlibStatus status);

/*
 * Reads the frame at `esp`. Every field goes through the accessor, so a frame
 * that crosses the end of a declared region is refused with the failing slot
 * named in *argument_index (one-based, in argument order: 1 = return PC,
 * 2 = handle, 3 = code, 4 = args). Returns PW_ERR_MALFORMED when a read fails.
 */
int pw_wine_unixlib_read_frame(PwUnixCallAccess guest, void *context,
                               uint32_t esp, PwWineUnixlibFrame *frame,
                               uint32_t *argument_index);

/*
 * Serves `unix_wine_dbg_write`. `params` is a guest pointer to
 * `struct wine_dbg_write_params { const char *str; unsigned int len; }`; both
 * the struct and the byte span it names are validated through the accessor and
 * the length is bounded by PW_WINE_UNIXLIB_MAX_DEBUG_BYTES before the sink is
 * asked to write. *length reports the delivered length for the evidence.
 */
PwWineUnixlibStatus pw_wine_unixlib_debug_write(PwUnixCallAccess guest,
                                                void *context, uint32_t params,
                                                const PwWineDebugSink *sink,
                                                uint32_t *length);

#endif /* PROSPERO_WIN_PW_WINE_UNIXLIB_H */
