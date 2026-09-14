/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_wine_thread.h"

#include "pw_wine_context.h"
#include "pw_wine_handle.h"

#include <string.h>

static void put_le32(uint8_t *out, uint32_t offset, uint32_t value)
{
    out[offset + 0u] = (uint8_t)(value & 0xffu);
    out[offset + 1u] = (uint8_t)((value >> 8) & 0xffu);
    out[offset + 2u] = (uint8_t)((value >> 16) & 0xffu);
    out[offset + 3u] = (uint8_t)((value >> 24) & 0xffu);
}

static uint32_t get_le32(const uint8_t *in, uint32_t offset)
{
    return (uint32_t)in[offset + 0u] |
           ((uint32_t)in[offset + 1u] << 8) |
           ((uint32_t)in[offset + 2u] << 16) |
           ((uint32_t)in[offset + 3u] << 24);
}

static uint16_t get_le16(const uint8_t *in, uint32_t offset)
{
    return (uint16_t)((uint16_t)in[offset + 0u] |
                      (uint16_t)((uint16_t)in[offset + 1u] << 8));
}

/*
 * NtGetNextThread: the next thread of this process after `last`, with a handle
 * to it.
 *
 * The loader walks its own thread list here while it gives every module with a
 * TLS directory its slot (alloc_tls_slot, dlls/ntdll/loader.c:1331), so the
 * shape is fixed: the current process, the handle the previous call returned
 * (or none), an access mask, no attributes, and one output handle. The
 * question "is there another thread" is answered by this run's own table, and
 * the end of the list is STATUS_NO_MORE_ENTRIES with a null handle written
 * back - which is what Wine's server returns, and what ends the loader's loop
 * (server/thread.c:2329).
 *
 * The handle is allocated only after the output span has been proved, so a
 * pointer the guest cannot receive into cannot leave a handle behind; if the
 * write itself fails, the handle goes back.
 */
int pw_wine_thread_next(struct PwWineCallContext *calls,
                        const PwUnixCallFrame *frame, PwUnixCallAccess guest,
                        void *context, uint32_t *status,
                        uint32_t *argument_index)
{
    const uint32_t process_handle = frame->args[0];
    const uint32_t last_handle = frame->args[1];
    const uint32_t desired_access = frame->args[2];
    const uint32_t attributes = frame->args[3];
    const uint32_t flags = frame->args[4];
    const uint32_t handle_pointer = frame->args[5];
    const PwWineThread *last = NULL;
    const PwWineThread *next = NULL;
    PwNtObject object;
    uint32_t probe = 0u;
    uint32_t handle = 0u;

    if (process_handle != 0xffffffffu) {
        *status = PW_NT_INVALID_HANDLE;
        calls->report->thread_refusals++;
        return PW_OK;
    }
    if (attributes != 0u || flags > 1u) {
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->thread_refusals++;
        return PW_OK;
    }
    if ((desired_access & ~(PW_WINE_THREAD_QUERY |
                            PW_WINE_THREAD_QUERY_LIMITED)) != 0u) {
        *status = PW_NT_ACCESS_DENIED;
        calls->report->thread_refusals++;
        return PW_OK;
    }
    if (handle_pointer == 0u) {
        *argument_index = 6u;
        return PW_ERR_MALFORMED;
    }
    /*
     * The output span is proved before anything is handed out. The probe is a
     * read: an address the guest can write a handle to is one it can read, and
     * a probe that wrote would change the guest's own memory to ask a
     * question.
     */
    if (guest(context, handle_pointer, &probe, 4u, 0) != PW_OK) {
        *argument_index = 6u;
        return PW_ERR_MALFORMED;
    }
    if (last_handle != 0u) {
        PwNtObject *found = NULL;
        unsigned kind = PW_NT_HANDLE_NONE;

        if (pw_wine_handle_lookup(calls, last_handle, &found, &kind) != PW_OK ||
            kind != PW_NT_HANDLE_THREAD || found->token == NULL) {
            *status = PW_NT_INVALID_HANDLE;
            calls->report->thread_refusals++;
            return PW_OK;
        }
        last = found->token;
        for (uint32_t index = 0u; index < calls->thread_count; ++index) {
            if (&calls->threads[index] != last)
                continue;
            if (index + 1u < calls->thread_count)
                next = &calls->threads[index + 1u];
            break;
        }
    } else if (calls->thread_count != 0u) {
        next = &calls->threads[0];
    }
    calls->report->thread_enumerations++;
    if (!next) {
        probe = 0u;
        if (guest(context, handle_pointer, &probe, 4u, 1) != PW_OK) {
            *argument_index = 6u;
            return PW_ERR_MALFORMED;
        }
        *status = PW_NT_NO_MORE_ENTRIES;
        return PW_OK;
    }
    if (pw_wine_handle_object((void *)next, 0u, NULL, &object) != PW_OK)
        return PW_ERR_PRECONDITION;
    if (pw_wine_handle_alloc(calls, &object, PW_NT_HANDLE_THREAD, &handle) !=
        PW_OK) {
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->thread_refusals++;
        return PW_OK;
    }
    if (guest(context, handle_pointer, &handle, 4u, 1) != PW_OK) {
        (void)pw_wine_handle_release(calls, handle);
        *argument_index = 6u;
        return PW_ERR_MALFORMED;
    }
    calls->report->thread_handles++;
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/*
 * NtQueryInformationThread, for the one class the loader asks about:
 * ThreadBasicInformation. alloc_tls_slot reads TebBaseAddress out of it and
 * then touches that TEB's TLS block (dlls/ntdll/loader.c:1370-1408), so the
 * answer has to be the TEB this run published - the same one the guest runs on
 * through FS - and not a value of its own.
 *
 * A class this run does not answer is refused rather than filled in, a handle
 * this run did not hand out is STATUS_INVALID_HANDLE, and a buffer shorter
 * than the structure is STATUS_INFO_LENGTH_MISMATCH, reported before anything
 * is written. The exit status is STATUS_PENDING, which is what Wine's server
 * answers for a thread that has not exited (server/thread.c:1819); the
 * priority fields are the ones this run models, and the comment in
 * pw_wine_thread.h says which.
 */
int pw_wine_thread_query(struct PwWineCallContext *calls,
                         const PwUnixCallFrame *frame, PwUnixCallAccess guest,
                         void *context, uint32_t *status,
                         uint32_t *argument_index)
{
    const uint32_t handle = frame->args[0];
    const uint32_t information_class = frame->args[1];
    const uint32_t information_pointer = frame->args[2];
    const uint32_t length = frame->args[3];
    const uint32_t result_pointer = frame->args[4];
    PwNtObject *object = NULL;
    unsigned kind = PW_NT_HANDLE_NONE;
    const PwWineThread *thread = NULL;
    uint8_t answer[PW_WINE_THREAD_BASIC_BYTES];
    const uint32_t needed = PW_WINE_THREAD_BASIC_BYTES;
    uint32_t written = needed;

    if (pw_wine_handle_lookup(calls, handle, &object, &kind) != PW_OK ||
        kind != PW_NT_HANDLE_THREAD || object->token == NULL) {
        *status = PW_NT_INVALID_HANDLE;
        calls->report->thread_refusals++;
        return PW_OK;
    }
    thread = object->token;
    if (information_class != 0u) {          /* ThreadBasicInformation */
        *status = PW_NT_INVALID_INFO_CLASS;
        calls->report->thread_refusals++;
        return PW_OK;
    }
    calls->report->thread_queries++;
    if (result_pointer != 0u &&
        guest(context, result_pointer, &written, 4u, 1) != PW_OK) {
        *argument_index = 5u;
        return PW_ERR_MALFORMED;
    }
    if (information_pointer == 0u || length < needed) {
        *status = PW_NT_INFO_LENGTH_MISMATCH;
        calls->report->thread_refusals++;
        return PW_OK;
    }
    memset(answer, 0, sizeof(answer));
    put_le32(answer, 0u, PW_WINE_THREAD_RUNNING);       /* ExitStatus */
    put_le32(answer, 4u, thread->teb_base);             /* TebBaseAddress */
    put_le32(answer, 8u, PW_GUEST_PROCESS_ID);          /* ClientId: process */
    put_le32(answer, 12u, thread->id);                  /* ClientId: thread */
    put_le32(answer, 16u, PW_WINE_THREAD_AFFINITY);     /* AffinityMask */
    put_le32(answer, 20u, PW_WINE_THREAD_PRIORITY);     /* Priority */
    put_le32(answer, 24u, PW_WINE_THREAD_BASE_PRIORITY);/* BasePriority */
    if (guest(context, information_pointer, answer, needed, 1) != PW_OK) {
        *argument_index = 3u;
        return PW_ERR_MALFORMED;
    }
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/*
 * NtContinue: install the state the guest's own context describes and resume
 * there, which is what makes a thread start.
 *
 * Wine's NtContinue is NtContinueEx with the boolean packed into a pointer
 * (dlls/ntdll/unix/server.c:2060), and that function waits for a pending user
 * APC when the caller asked to be alerted and otherwise ends in
 * signal_set_full_context: the context is loaded into the CPU and the call
 * does not return to its caller. This run models no APC queue at all -
 * NtQueueApcThread has no handler, so nothing can ever be pending - which
 * makes "there is no APC to deliver" the truthful answer and the context the
 * thing that decides where execution goes.
 *
 * What is installed is the whole integer and control state - Eax..Edi, Eip,
 * Esp and Eflags - plus the two floating-point control words, which the
 * context carries at fixed offsets and this run's FP state has as its own
 * fields. What is *not* modelled is recorded here rather than left implicit,
 * and each is refused or ignored in a way the guest can see:
 *
 *  - the segment selectors. A context that does not name the user code and
 *    stack segments this run publishes (0x1b/0x23, the ones the kernel puts in
 *    the context it builds) is refused with STATUS_INVALID_PARAMETER, because
 *    running in a segment this gate cannot describe is not something it can
 *    do. FS is not modelled as a selector at all - the run addresses the TEB
 *    by base - so SegFs and SegGs are ignored and the FS base the process unit
 *    published stays.
 *  - the floating-point register files. The x87 register area and the XMM file
 *    are the run's own FP state and are not rebuilt from this context.
 */
int pw_wine_thread_continue(struct PwWineCallContext *calls,
                            const PwUnixCallFrame *frame,
                            PwUnixCallAccess guest, void *context,
                            uint32_t *status, uint32_t *argument_index)
{
    PwX86State *state = context;
    const uint32_t pointer = frame->args[0];
    uint8_t raw[PW_WINE_CONTEXT_BYTES];
    const uint32_t required = PW_WINE_CONTEXT_FLAG_i386 |
                              PW_WINE_CONTEXT_FLAG_CONTROL |
                              PW_WINE_CONTEXT_FLAG_INTEGER;
    uint32_t flags;

    if (!calls || !state || !guest || pointer == 0u) {
        *argument_index = 0u;
        return PW_ERR_MALFORMED;
    }
    if (guest(context, pointer, raw, sizeof(raw), 0) != PW_OK) {
        *argument_index = 0u;
        return PW_ERR_MALFORMED;
    }
    flags = get_le32(raw, PW_WINE_CONTEXT_OFFSET_FLAGS);
    if ((flags & required) != required) {
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->context_restore_refusals++;
        return PW_OK;
    }
    if (get_le16(raw, PW_WINE_CONTEXT_OFFSET_SEG_CS) !=
            (uint16_t)PW_WINE_CONTEXT_USER_CS ||
        get_le16(raw, PW_WINE_CONTEXT_OFFSET_SEG_SS) !=
            (uint16_t)PW_WINE_CONTEXT_USER_SS) {
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->context_restore_refusals++;
        return PW_OK;
    }
    state->gpr[0] = get_le32(raw, PW_WINE_CONTEXT_OFFSET_EAX);
    state->gpr[1] = get_le32(raw, PW_WINE_CONTEXT_OFFSET_ECX);
    state->gpr[2] = get_le32(raw, PW_WINE_CONTEXT_OFFSET_EDX);
    state->gpr[3] = get_le32(raw, PW_WINE_CONTEXT_OFFSET_EBX);
    state->gpr[4] = get_le32(raw, PW_WINE_CONTEXT_OFFSET_ESP);
    state->gpr[5] = get_le32(raw, PW_WINE_CONTEXT_OFFSET_EBP);
    state->gpr[6] = get_le32(raw, PW_WINE_CONTEXT_OFFSET_ESI);
    state->gpr[7] = get_le32(raw, PW_WINE_CONTEXT_OFFSET_EDI);
    state->eip = get_le32(raw, PW_WINE_CONTEXT_OFFSET_EIP);
    /* The flags come from the context whole, so nothing the run deferred from
     * an earlier instruction may be merged into them afterwards. */
    state->eflags = get_le32(raw, PW_WINE_CONTEXT_OFFSET_EFLAGS);
    state->deferred_flags.raw_flags = 0u;
    state->deferred_flags.known_mask = 0u;
    state->fp.x87_control = get_le16(raw, PW_WINE_CONTEXT_OFFSET_FLOAT_CONTROL);
    state->fp.mxcsr = get_le32(raw, PW_WINE_CONTEXT_OFFSET_EXTENDED_MXCSR);
    /*
     * The instruction pointer and the stack are now the context's, so the
     * dispatcher must not synthesize the stub's own return over them.
     */
    calls->state_installed = 1u;
    calls->report->context_restores++;
    *status = PW_NT_SUCCESS;
    return PW_OK;
}
