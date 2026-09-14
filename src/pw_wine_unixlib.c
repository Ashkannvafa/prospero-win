/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_wine_unixlib.h"

#include <string.h>

const char *pw_wine_unixlib_status_name(PwWineUnixlibStatus status)
{
    switch (status) {
    case PW_WINE_UNIXLIB_OK: return "ok";
    case PW_WINE_UNIXLIB_MALFORMED: return "malformed-frame";
    case PW_WINE_UNIXLIB_UNKNOWN_HANDLE: return "unknown-handle";
    case PW_WINE_UNIXLIB_UNKNOWN_CODE: return "unknown-code";
    case PW_WINE_UNIXLIB_SERVICE_FAILED: return "service-failed";
    case PW_WINE_UNIXLIB_UNIMPLEMENTED: return "unimplemented";
    }
    return "unknown";
}

int pw_wine_unixlib_read_frame(PwUnixCallAccess guest, void *context,
                               uint32_t esp, PwWineUnixlibFrame *frame,
                               uint32_t *argument_index)
{
    uint8_t raw[PW_WINE_UNIXLIB_FRAME_BYTES];

    if (!guest || !frame)
        return PW_ERR_PRECONDITION;
    /*
     * One validated read of the whole frame: either all sixteen bytes the
     * dispatcher would read are inside memory the guest may read, or the call
     * is refused. A partial frame is never serviced.
     */
    if (guest(context, esp, raw, sizeof(raw), 0) != PW_OK) {
        if (argument_index)
            *argument_index = 1u;
        return PW_ERR_MALFORMED;
    }
    memcpy(&frame->return_pc, raw, 4u);
    memcpy(&frame->handle, raw + PW_WINE_UNIXLIB_HANDLE_OFFSET, 4u);
    memcpy(&frame->code, raw + PW_WINE_UNIXLIB_CODE_OFFSET, 4u);
    memcpy(&frame->args, raw + PW_WINE_UNIXLIB_ARGS_OFFSET, 4u);
    return PW_OK;
}

PwWineUnixlibStatus pw_wine_unixlib_debug_write(PwUnixCallAccess guest,
                                                void *context, uint32_t params,
                                                const PwWineDebugSink *sink,
                                                uint32_t *length)
{
    uint8_t header[PW_UNIXLIB_DBG_WRITE_PARAMS_BYTES];
    uint8_t bytes[PW_WINE_UNIXLIB_MAX_DEBUG_BYTES];
    uint32_t string = 0u;
    uint32_t count = 0u;

    if (length)
        *length = 0u;
    if (!guest || !sink || !sink->write)
        return PW_WINE_UNIXLIB_SERVICE_FAILED;
    /*
     * The params struct lives in guest memory and holds a guest pointer: both
     * halves go through the accessor, and the pointer is never dereferenced by
     * this unit.
     */
    if (guest(context, params, header, sizeof(header), 0) != PW_OK)
        return PW_WINE_UNIXLIB_MALFORMED;
    memcpy(&string, header + PW_UNIXLIB_DBG_WRITE_STR_OFFSET, 4u);
    memcpy(&count, header + PW_UNIXLIB_DBG_WRITE_LEN_OFFSET, 4u);
    if (count > (uint32_t)PW_WINE_UNIXLIB_MAX_DEBUG_BYTES)
        return PW_WINE_UNIXLIB_MALFORMED;
    if (count == 0u) {
        /* A zero-length write is answered, not refused: the CU side would
         * write nothing and succeed. */
        return sink->write(sink->context, bytes, 0u) == 0
                   ? PW_WINE_UNIXLIB_OK
                   : PW_WINE_UNIXLIB_SERVICE_FAILED;
    }
    if (guest(context, string, bytes, count, 0) != PW_OK)
        return PW_WINE_UNIXLIB_MALFORMED;
    if (sink->write(sink->context, bytes, count) != 0)
        return PW_WINE_UNIXLIB_SERVICE_FAILED;
    if (length)
        *length = count;
    return PW_WINE_UNIXLIB_OK;
}
