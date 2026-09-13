/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_unix_call.h"

#include <string.h>

/*
 * The first 64 entries of Wine's i386 PE syscall table
 * (ALL_SYSCALLS32 in dlls/ntdll/ntsyscalls.h at the pinned revision). The
 * argument width is what the stub leaves on the stack, in bytes, and is what
 * the bridge must pop for the stub's "ret imm16" contract to hold.
 *
 * The table is deliberately short: it covers the range a first boot attempt
 * reaches, and every entry is cross-checked against the pinned source by
 * tests/test_unix_call_table.py rather than trusted from memory. Extending it
 * is mechanical and must keep that check green.
 */
static const PwUnixCallInfo table[] = {
    { 0x0000u, "NtAccessCheck", 32u },
    { 0x0001u, "NtWorkerFactoryWorkerReady", 4u },
    { 0x0002u, "NtAcceptConnectPort", 24u },
    { 0x0003u, "NtMapUserPhysicalPagesScatter", 0u },
    { 0x0004u, "NtWaitForSingleObject", 12u },
    { 0x0005u, "NtCallbackReturn", 12u },
    { 0x0006u, "NtReadFile", 36u },
    { 0x0007u, "NtDeviceIoControlFile", 40u },
    { 0x0008u, "NtWriteFile", 36u },
    { 0x0009u, "NtRemoveIoCompletion", 20u },
    { 0x000au, "NtReleaseSemaphore", 12u },
    { 0x000bu, "NtReplyWaitReceivePort", 16u },
    { 0x000cu, "NtReplyPort", 8u },
    { 0x000du, "NtSetInformationThread", 16u },
    { 0x000eu, "NtSetEvent", 8u },
    { 0x000fu, "NtClose", 4u },
    { 0x0010u, "NtQueryObject", 20u },
    { 0x0011u, "NtQueryInformationFile", 20u },
    { 0x0012u, "NtOpenKey", 12u },
    { 0x0013u, "NtEnumerateValueKey", 24u },
    { 0x0014u, "NtFindAtom", 12u },
    { 0x0015u, "NtQueryDefaultLocale", 8u },
    { 0x0016u, "NtQueryKey", 20u },
    { 0x0017u, "NtQueryValueKey", 24u },
    { 0x0018u, "NtAllocateVirtualMemory", 24u },
    { 0x0019u, "NtQueryInformationProcess", 20u },
    { 0x001au, "NtWaitForMultipleObjects32", 0u },
    { 0x001bu, "NtWriteFileGather", 36u },
    { 0x001cu, "NtSetInformationProcess", 16u },
    { 0x001du, "NtCreateKey", 28u },
    { 0x001eu, "NtFreeVirtualMemory", 16u },
    { 0x001fu, "NtImpersonateClientOfPort", 8u },
    { 0x0020u, "NtReleaseMutant", 8u },
    { 0x0021u, "NtQueryInformationToken", 20u },
    { 0x0022u, "NtRequestWaitReplyPort", 12u },
    { 0x0023u, "NtQueryVirtualMemory", 24u },
    { 0x0024u, "NtOpenThreadToken", 16u },
    { 0x0025u, "NtQueryInformationThread", 20u },
    { 0x0026u, "NtOpenProcess", 16u },
    { 0x0027u, "NtSetInformationFile", 20u },
    { 0x0028u, "NtMapViewOfSection", 40u },
    { 0x0029u, "NtAccessCheckAndAuditAlarm", 44u },
    { 0x002au, "NtUnmapViewOfSection", 8u },
    { 0x002bu, "NtReplyWaitReceivePortEx", 20u },
    { 0x002cu, "NtTerminateProcess", 8u },
    { 0x002du, "NtSetEventBoostPriority", 4u },
    { 0x002eu, "NtReadFileScatter", 36u },
    { 0x002fu, "NtOpenThreadTokenEx", 20u },
    { 0x0030u, "NtOpenProcessTokenEx", 16u },
    { 0x0031u, "NtQueryPerformanceCounter", 8u },
    { 0x0032u, "NtEnumerateKey", 24u },
    { 0x0033u, "NtOpenFile", 24u },
    { 0x0034u, "NtDelayExecution", 8u },
    { 0x0035u, "NtQueryDirectoryFile", 44u },
    { 0x0036u, "NtQuerySystemInformation", 16u },
    { 0x0037u, "NtOpenSection", 12u },
    { 0x0038u, "NtQueryTimer", 20u },
    { 0x0039u, "NtFsControlFile", 40u },
    { 0x003au, "NtWriteVirtualMemory", 20u },
    { 0x003bu, "NtCloseObjectAuditAlarm", 12u },
    { 0x003cu, "NtDuplicateObject", 28u },
    { 0x003du, "NtQueryAttributesFile", 8u },
    { 0x003eu, "NtClearEvent", 4u },
    { 0x003fu, "NtReadVirtualMemory", 20u },
};

const PwUnixCallInfo *pw_unix_call_lookup(uint32_t id)
{
    for (uint32_t index = 0; index < sizeof(table) / sizeof(table[0]); ++index)
        if (table[index].id == id)
            return &table[index];
    return NULL;
}

uint32_t pw_unix_call_table_count(void)
{
    return (uint32_t)(sizeof(table) / sizeof(table[0]));
}

const PwUnixCallInfo *pw_unix_call_table_entry(uint32_t index)
{
    if (index >= sizeof(table) / sizeof(table[0]))
        return NULL;
    return &table[index];
}

static void unpin(const PwUnixCallInfo *info, uint32_t *argument_index)
{
    if (argument_index)
        *argument_index = info->arg_bytes / 4u;
}

int pw_unix_call_read(const PwUnixCallInfo *info,
                      PwUnixCallAccess guest_access, void *context,
                      uint32_t esp, PwUnixCallFrame *frame,
                      uint32_t *argument_index)
{
    uint32_t words;

    if (!info || !guest_access || !frame)
        return PW_ERR_PRECONDITION;
    if (info->arg_bytes % 4u != 0u ||
        info->arg_bytes / 4u > PW_UNIX_CALL_MAX_ARGS)
        return PW_ERR_UNSUPPORTED;
    memset(frame, 0, sizeof(*frame));
    frame->id = info->id;
    frame->arg_bytes = info->arg_bytes;
    frame->esp = esp;
    if (argument_index)
        *argument_index = 0u;
    /* [esp] is the stub's own return address and [esp+4] the caller's; the
     * arguments begin above both of them. */
    if (guest_access(context, esp, &frame->stub_return_pc, 4u, 0) != PW_OK ||
        guest_access(context, esp + 4u, &frame->return_pc, 4u, 0) != PW_OK) {
        if (argument_index)
            *argument_index = 0u;
        return PW_ERR_MALFORMED;
    }
    words = info->arg_bytes / 4u;
    for (uint32_t index = 0; index < words; ++index) {
        if (guest_access(context, esp + 8u + index * 4u, &frame->args[index], 4u,
                   0) != PW_OK) {
            if (argument_index)
                *argument_index = index + 1u;
            return PW_ERR_MALFORMED;
        }
    }
    unpin(info, argument_index);
    return PW_OK;
}

void pw_unix_call_record(PwUnixCallTally *tally, const PwUnixCallFrame *frame,
                         const PwUnixCallInfo *info, uint32_t status,
                         uint32_t argument_index, PwUnixCallOutcome outcome)
{
    PwUnixCallRecord *record;

    if (!tally)
        return;
    switch (outcome) {
    case PW_UNIX_CALL_HANDLED: tally->handled++; break;
    case PW_UNIX_CALL_UNIMPLEMENTED: tally->unimplemented++; break;
    case PW_UNIX_CALL_UNKNOWN: tally->unknown++; break;
    case PW_UNIX_CALL_REJECTED: tally->rejected++; break;
    default: break;
    }
    if (tally->records >= PW_UNIX_CALL_MAX_SEQUENCE)
        return;
    record = &tally->sequence[tally->records++];
    memset(record, 0, sizeof(*record));
    record->id = frame ? frame->id : 0u;
    record->arg_bytes = info ? info->arg_bytes : 0u;
    record->stub_return_pc = frame ? frame->stub_return_pc : 0u;
    record->return_pc = frame ? frame->return_pc : 0u;
    record->status = status;
    record->argument_index = argument_index;
    record->outcome = outcome;
    if (info && info->name) {
        const size_t length = strlen(info->name);

        if (length <= PW_UNIX_CALL_NAME_MAX)
            memcpy(record->name, info->name, length + 1u);
    }
    if (frame) {
        const uint32_t words = frame->arg_bytes / 4u;

        record->esp = frame->esp;
        record->argument_count =
            words > PW_UNIX_CALL_MAX_ARGS ? PW_UNIX_CALL_MAX_ARGS : words;
        for (uint32_t index = 0; index < record->argument_count; ++index)
            record->args[index] = frame->args[index];
    }
}

const char *pw_unix_call_outcome_name(PwUnixCallOutcome outcome)
{
    switch (outcome) {
    case PW_UNIX_CALL_HANDLED: return "handled";
    case PW_UNIX_CALL_UNIMPLEMENTED: return "unimplemented";
    case PW_UNIX_CALL_UNKNOWN: return "unknown";
    case PW_UNIX_CALL_REJECTED: return "rejected";
    default: return "none";
    }
}
