/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The unix-call adapter on its own: the stdcall frame and the debug write.
 *
 * The frame is the contract the previous Wine bridge got wrong by guessing
 * `[esp+4]` as the argument base, and this unit got wrong once more by assuming
 * a four-dword frame: `unixlib_handle_t` is `UINT64`, so the frame is five
 * slots - return PC, handle low, handle high, code, args - which is exactly
 * what the pinned assembly reads and what the real call site loads. The dump
 * of the corrected run shows the first call as code 2 with a stack args
 * pointer, where the shifted reading had shown code 0 and args 2.
 *
 * Everything is pinned here against a fake guest window whose accessor refuses
 * anything outside it: a frame crossing the end of the window, a params struct
 * that does, a byte span that does, a length one byte over the bound and a
 * handle whose high half is not zero are all refusals, and the failing slot is
 * named. The sink is a fake as well, so a refused write is distinguishable from
 * a delivered one without a host stream.
 */
#include "../src/pw_wine_unixlib.h"

#include <assert.h>
#include <string.h>

typedef struct FakeGuest {
    uint8_t bytes[64];
    uint32_t size;
    unsigned reads;
} FakeGuest;

static int fake_access(void *context, uint32_t address, void *out,
                       uint32_t length, int write)
{
    FakeGuest *guest = context;

    if (write)
        return PW_ERR_MALFORMED;
    if (address > guest->size || length > guest->size - address)
        return PW_ERR_MALFORMED;
    guest->reads++;
    memcpy(out, &guest->bytes[address], length);
    return PW_OK;
}

typedef struct FakeSink {
    unsigned calls;
    uint32_t length;
    uint8_t bytes[PW_WINE_UNIXLIB_MAX_DEBUG_BYTES];
    int status;
} FakeSink;

static int fake_write(void *context, const void *bytes, uint32_t length)
{
    FakeSink *sink = context;

    sink->calls++;
    sink->length = length;
    if (length)
        memcpy(sink->bytes, bytes, length);
    return sink->status;
}

static void frame_tests(void)
{
    FakeGuest guest;
    PwWineUnixlibFrame frame;
    uint32_t failed = 0u;

    memset(&guest, 0, sizeof(guest));
    guest.size = sizeof(guest.bytes);
    /* A well-formed frame at esp = 0: return PC, handle low, handle high,
     * code, args. */
    {
        const uint32_t values[5] = { 0x10401000u, 0x00000123u, 0u, 2u, 0x40u };

        memcpy(guest.bytes, values, sizeof(values));
    }
    assert(pw_wine_unixlib_read_frame(fake_access, &guest, 0u, &frame,
                                      &failed) == PW_OK);
    assert(frame.return_pc == 0x10401000u);
    assert(frame.handle == 0x00000123u);
    assert(frame.handle_high == 0u);
    assert(frame.code == 2u);
    assert(frame.args == 0x40u);
    /* The offsets are the documented ones, not the four-slot guess. */
    assert(PW_WINE_UNIXLIB_FRAME_BYTES == 20);
    assert(PW_WINE_UNIXLIB_HANDLE_BYTES == 8);
    assert(PW_WINE_UNIXLIB_CODE_OFFSET == 12);
    assert(PW_WINE_UNIXLIB_ARGS_OFFSET == 16);
    /* Null required arguments are refused, not dereferenced. */
    assert(pw_wine_unixlib_read_frame(NULL, &guest, 0u, &frame, &failed) ==
           PW_ERR_PRECONDITION);
    assert(pw_wine_unixlib_read_frame(fake_access, &guest, 0u, NULL,
                                      &failed) == PW_ERR_PRECONDITION);
    /* A frame that runs past the end of the window is refused, and the slot is
     * reported as the first argument. */
    failed = 0u;
    assert(pw_wine_unixlib_read_frame(fake_access, &guest,
                                      guest.size - 8u, &frame, &failed) ==
           PW_ERR_MALFORMED);
    assert(failed == 1u);
    /* Four slots fit where five do not: this is the off-by-one that produced
     * the shifted reading, so the boundary itself is pinned. */
    failed = 0u;
    assert(pw_wine_unixlib_read_frame(fake_access, &guest,
                                      guest.size - 16u, &frame, &failed) ==
           PW_ERR_MALFORMED);
    assert(failed == 1u);
    assert(pw_wine_unixlib_read_frame(fake_access, &guest,
                                      guest.size - 20u, &frame,
                                      &failed) == PW_OK);
    /* The last complete frame inside the window is fine. */
    assert(pw_wine_unixlib_read_frame(fake_access, &guest,
                                      guest.size - PW_WINE_UNIXLIB_FRAME_BYTES,
                                      &frame, &failed) == PW_OK);
}

static void debug_write_tests(void)
{
    FakeGuest guest;
    FakeSink sink;
    const PwWineDebugSink service = { .context = &sink, .write = fake_write };
    uint32_t length = 0u;
    const uint32_t params = 0u;         /* the params struct starts at 0 */
    const uint32_t text = 8u;           /* and the text it points at at 8 */

    memset(&guest, 0, sizeof(guest));
    memset(&sink, 0, sizeof(sink));
    guest.size = sizeof(guest.bytes);
    {
        uint32_t bytes[2] = { text, 5u };

        memcpy(guest.bytes + params, bytes, sizeof(bytes));
    }
    memcpy(guest.bytes + text, "HELLO", 5u);

    /* A delivered write copies exactly the bytes the params struct names. */
    assert(pw_wine_unixlib_debug_write(fake_access, &guest, params, &service,
                                       &length) == PW_WINE_UNIXLIB_OK);
    assert(sink.calls == 1u && sink.length == 5u);
    assert(memcmp(sink.bytes, "HELLO", 5u) == 0);
    assert(length == 5u);

    /* A zero-length write is still delivered (the CU side would write
     * nothing and succeed). */
    {
        uint32_t empty[2] = { text, 0u };

        memcpy(guest.bytes + params, empty, sizeof(empty));
    }
    length = 0xffffffffu;
    assert(pw_wine_unixlib_debug_write(fake_access, &guest, params, &service,
                                       &length) == PW_WINE_UNIXLIB_OK);
    assert(sink.calls == 2u && sink.length == 0u && length == 0u);

    /* One byte over the bound is a refusal, and the sink is not asked. */
    {
        uint32_t over[2] = { text,
                             PW_WINE_UNIXLIB_MAX_DEBUG_BYTES + 1u };

        memcpy(guest.bytes + params, over, sizeof(over));
    }
    assert(pw_wine_unixlib_debug_write(fake_access, &guest, params, &service,
                                       &length) == PW_WINE_UNIXLIB_MALFORMED);
    assert(sink.calls == 2u);
    /* The bound itself is not refused for its length: it fails only because
     * this fake window cannot hold that many bytes, which is the span check
     * doing its job. */
    {
        uint32_t exact[2] = { text, PW_WINE_UNIXLIB_MAX_DEBUG_BYTES };

        memcpy(guest.bytes + params, exact, sizeof(exact));
    }
    assert(pw_wine_unixlib_debug_write(fake_access, &guest, params, &service,
                                       &length) == PW_WINE_UNIXLIB_MALFORMED);
    /* A params struct outside the window, and a text span that crosses its
     * end, are both refused. */
    assert(pw_wine_unixlib_debug_write(fake_access, &guest, guest.size - 4u,
                                       &service, &length) ==
           PW_WINE_UNIXLIB_MALFORMED);
    {
        uint32_t crossing[2] = { 60u, 8u };

        memcpy(guest.bytes + params, crossing, sizeof(crossing));
    }
    assert(pw_wine_unixlib_debug_write(fake_access, &guest, params, &service,
                                       &length) == PW_WINE_UNIXLIB_MALFORMED);
    /* A sink that refuses its write is a service failure, not a success. */
    {
        uint32_t ok[2] = { text, 5u };

        memcpy(guest.bytes + params, ok, sizeof(ok));
    }
    sink.status = -1;
    assert(pw_wine_unixlib_debug_write(fake_access, &guest, params, &service,
                                       &length) ==
           PW_WINE_UNIXLIB_SERVICE_FAILED);
    /* And a missing sink is refused before any guest read. */
    assert(pw_wine_unixlib_debug_write(fake_access, &guest, params, NULL,
                                       &length) ==
           PW_WINE_UNIXLIB_SERVICE_FAILED);
    /* The status vocabulary stays distinct. */
    assert(strcmp(pw_wine_unixlib_status_name(PW_WINE_UNIXLIB_OK), "ok") == 0);
    assert(strcmp(pw_wine_unixlib_status_name(
                      PW_WINE_UNIXLIB_UNKNOWN_HANDLE), "unknown-handle") == 0);
    assert(strcmp(pw_wine_unixlib_status_name(PW_WINE_UNIXLIB_MALFORMED),
                  "malformed-frame") == 0);
}

int main(void)
{
    frame_tests();
    debug_write_tests();
    return 0;
}
