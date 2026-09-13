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
    { 0x0040u, "NtOpenEvent", 12u },
    { 0x0041u, "NtAdjustPrivilegesToken", 24u },
    { 0x0042u, "NtDuplicateToken", 24u },
    { 0x0043u, "NtContinue", 8u },
    { 0x0044u, "NtQueryDefaultUILanguage", 4u },
    { 0x0045u, "NtQueueApcThread", 20u },
    { 0x0046u, "NtYieldExecution", 0u },
    { 0x0047u, "NtAddAtom", 12u },
    { 0x0048u, "NtCreateEvent", 20u },
    { 0x0049u, "NtQueryVolumeInformationFile", 20u },
    { 0x004au, "NtCreateSection", 28u },
    { 0x004bu, "NtFlushBuffersFile", 8u },
    { 0x004cu, "NtApphelpCacheControl", 0u },
    { 0x004du, "NtCreateProcessEx", 0u },
    { 0x004eu, "NtCreateThread", 32u },
    { 0x004fu, "NtIsProcessInJob", 8u },
    { 0x0050u, "NtProtectVirtualMemory", 20u },
    { 0x0051u, "NtQuerySection", 20u },
    { 0x0052u, "NtResumeThread", 8u },
    { 0x0053u, "NtTerminateThread", 8u },
    { 0x0054u, "NtReadRequestData", 24u },
    { 0x0055u, "NtCreateFile", 44u },
    { 0x0056u, "NtQueryEvent", 20u },
    { 0x0057u, "NtWriteRequestData", 24u },
    { 0x0058u, "NtOpenDirectoryObject", 12u },
    { 0x0059u, "NtAccessCheckByTypeAndAuditAlarm", 64u },
    { 0x005au, "NtQuerySystemTime", 4u },
    { 0x005bu, "NtWaitForMultipleObjects", 20u },
    { 0x005cu, "NtSetInformationObject", 16u },
    { 0x005du, "NtCancelIoFile", 8u },
    { 0x005eu, "NtTraceEvent", 0u },
    { 0x005fu, "NtPowerInformation", 20u },
    { 0x0060u, "NtSetValueKey", 24u },
    { 0x0061u, "NtCancelTimer", 8u },
    { 0x0062u, "NtSetTimer", 28u },
    { 0x0063u, "NtAdjustGroupsToken", 24u },
    { 0x0064u, "NtAlertMultipleThreadByThreadId", 16u },
    { 0x0065u, "NtAlertResumeThread", 8u },
    { 0x0066u, "NtAlertThread", 4u },
    { 0x0067u, "NtAlertThreadByThreadId", 4u },
    { 0x0068u, "NtAllocateLocallyUniqueId", 4u },
    { 0x0069u, "NtAllocateReserveObject", 12u },
    { 0x006au, "NtAllocateUuids", 16u },
    { 0x006bu, "NtAllocateVirtualMemoryEx", 28u },
    { 0x006cu, "NtAlpcAcceptConnectPort", 36u },
    { 0x006du, "NtAlpcConnectPort", 44u },
    { 0x006eu, "NtAlpcCreatePort", 12u },
    { 0x006fu, "NtAlpcDisconnectPort", 8u },
    { 0x0070u, "NtAlpcImpersonateClientOfPort", 12u },
    { 0x0071u, "NtAlpcSendWaitReceivePort", 32u },
    { 0x0072u, "NtAreMappedFilesTheSame", 8u },
    { 0x0073u, "NtAssignProcessToJobObject", 8u },
    { 0x0074u, "NtCancelIoFileEx", 12u },
    { 0x0075u, "NtCancelSynchronousIoFile", 12u },
    { 0x0076u, "NtCommitTransaction", 8u },
    { 0x0077u, "NtCompareObjects", 8u },
    { 0x0078u, "NtCompareTokens", 12u },
    { 0x0079u, "NtCompleteConnectPort", 4u },
    { 0x007au, "NtConnectPort", 32u },
    { 0x007bu, "NtContinueEx", 8u },
    { 0x007cu, "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter", 16u },
    { 0x007du, "NtCreateDirectoryObject", 12u },
    { 0x007eu, "NtCreateIoCompletion", 16u },
    { 0x007fu, "NtCreateJobObject", 12u },
    { 0x0080u, "NtCreateKeyTransacted", 32u },
    { 0x0081u, "NtCreateKeyedEvent", 16u },
    { 0x0082u, "NtCreateLowBoxToken", 36u },
    { 0x0083u, "NtCreateMailslotFile", 32u },
    { 0x0084u, "NtCreateMutant", 16u },
    { 0x0085u, "NtCreateNamedPipeFile", 56u },
    { 0x0086u, "NtCreatePagingFile", 16u },
    { 0x0087u, "NtCreatePort", 20u },
    { 0x0088u, "NtCreateSectionEx", 36u },
    { 0x0089u, "NtCreateSemaphore", 20u },
    { 0x008au, "NtCreateSymbolicLinkObject", 16u },
    { 0x008bu, "NtCreateThreadEx", 44u },
    { 0x008cu, "NtCreateTimer", 16u },
    { 0x008du, "NtCreateToken", 52u },
    { 0x008eu, "NtCreateTransaction", 40u },
    { 0x008fu, "NtCreateUserProcess", 44u },
    { 0x0090u, "NtDebugActiveProcess", 8u },
    { 0x0091u, "NtDebugContinue", 12u },
    { 0x0092u, "NtDeleteAtom", 4u },
    { 0x0093u, "NtDeleteFile", 4u },
    { 0x0094u, "NtDeleteKey", 4u },
    { 0x0095u, "NtDeleteValueKey", 8u },
    { 0x0096u, "NtDisplayString", 4u },
    { 0x0097u, "NtFilterToken", 24u },
    { 0x0098u, "NtFlushBuffersFileEx", 20u },
    { 0x0099u, "NtFlushInstructionCache", 12u },
    { 0x009au, "NtFlushKey", 4u },
    { 0x009bu, "NtFlushProcessWriteBuffers", 0u },
    { 0x009cu, "NtFlushVirtualMemory", 16u },
    { 0x009du, "NtGetContextThread", 8u },
    { 0x009eu, "NtGetCurrentProcessorNumber", 0u },
    { 0x009fu, "NtGetNextProcess", 20u },
    { 0x00a0u, "NtGetNextThread", 24u },
    { 0x00a1u, "NtGetNlsSectionPtr", 20u },
    { 0x00a2u, "NtGetWriteWatch", 28u },
    { 0x00a3u, "NtImpersonateAnonymousToken", 4u },
    { 0x00a4u, "NtInitializeNlsFiles", 12u },
    { 0x00a5u, "NtInitiatePowerAction", 16u },
    { 0x00a6u, "NtCreateDebugObject", 16u },
    { 0x00a7u, "NtListenPort", 8u },
    { 0x00a8u, "NtLoadDriver", 4u },
    { 0x00a9u, "NtLoadKey", 8u },
    { 0x00aau, "NtLoadKey2", 12u },
    { 0x00abu, "NtLoadKeyEx", 32u },
    { 0x00acu, "NtLockFile", 40u },
    { 0x00adu, "NtLockVirtualMemory", 16u },
    { 0x00aeu, "NtMakePermanentObject", 4u },
    { 0x00afu, "NtMakeTemporaryObject", 4u },
    { 0x00b0u, "NtMapViewOfSectionEx", 36u },
    { 0x00b1u, "NtNotifyChangeDirectoryFile", 36u },
    { 0x00b2u, "NtNotifyChangeKey", 40u },
    { 0x00b3u, "NtNotifyChangeMultipleKeys", 48u },
    { 0x00b4u, "NtOpenIoCompletion", 12u },
    { 0x00b5u, "NtOpenJobObject", 12u },
    { 0x00b6u, "NtOpenKeyEx", 16u },
    { 0x00b7u, "NtOpenKeyTransacted", 16u },
    { 0x00b8u, "NtOpenKeyTransactedEx", 20u },
    { 0x00b9u, "NtOpenKeyedEvent", 12u },
    { 0x00bau, "NtOpenMutant", 12u },
    { 0x00bbu, "NtOpenProcessToken", 12u },
    { 0x00bcu, "NtOpenSemaphore", 12u },
    { 0x00bdu, "NtOpenSymbolicLinkObject", 12u },
    { 0x00beu, "NtOpenThread", 16u },
    { 0x00bfu, "NtOpenTimer", 12u },
    { 0x00c0u, "NtPrivilegeCheck", 12u },
    { 0x00c1u, "NtPulseEvent", 8u },
    { 0x00c2u, "NtQueryDirectoryObject", 28u },
    { 0x00c3u, "NtQueryEaFile", 36u },
    { 0x00c4u, "NtQueryFullAttributesFile", 8u },
    { 0x00c5u, "NtQueryInformationAtom", 20u },
    { 0x00c6u, "NtQueryInformationJobObject", 20u },
    { 0x00c7u, "NtQueryInstallUILanguage", 4u },
    { 0x00c8u, "NtQueryIoCompletion", 20u },
    { 0x00c9u, "NtQueryLicenseValue", 20u },
    { 0x00cau, "NtQueryMultipleValueKey", 24u },
    { 0x00cbu, "NtQueryMutant", 20u },
    { 0x00ccu, "NtQuerySecurityObject", 20u },
    { 0x00cdu, "NtQuerySemaphore", 20u },
    { 0x00ceu, "NtQuerySymbolicLinkObject", 12u },
    { 0x00cfu, "NtQuerySystemEnvironmentValue", 16u },
    { 0x00d0u, "NtQuerySystemEnvironmentValueEx", 20u },
    { 0x00d1u, "NtQuerySystemInformationEx", 24u },
    { 0x00d2u, "NtQueryTimerResolution", 12u },
    { 0x00d3u, "NtQueueApcThreadEx", 24u },
    { 0x00d4u, "NtQueueApcThreadEx2", 28u },
    { 0x00d5u, "NtRaiseException", 12u },
    { 0x00d6u, "NtRaiseHardError", 24u },
    { 0x00d7u, "NtRegisterThreadTerminatePort", 4u },
    { 0x00d8u, "NtReleaseKeyedEvent", 16u },
    { 0x00d9u, "NtRemoveIoCompletionEx", 24u },
    { 0x00dau, "NtRemoveProcessDebug", 8u },
    { 0x00dbu, "NtRenameKey", 8u },
    { 0x00dcu, "NtReplaceKey", 12u },
    { 0x00ddu, "NtResetEvent", 8u },
    { 0x00deu, "NtResetWriteWatch", 12u },
    { 0x00dfu, "NtRestoreKey", 12u },
    { 0x00e0u, "NtResumeProcess", 4u },
    { 0x00e1u, "NtRollbackTransaction", 8u },
    { 0x00e2u, "NtSaveKey", 8u },
    { 0x00e3u, "NtSecureConnectPort", 36u },
    { 0x00e4u, "NtSetContextThread", 8u },
    { 0x00e5u, "NtSetDebugFilterState", 12u },
    { 0x00e6u, "NtSetDefaultLocale", 8u },
    { 0x00e7u, "NtSetDefaultUILanguage", 4u },
    { 0x00e8u, "NtSetEaFile", 16u },
    { 0x00e9u, "NtSetInformationDebugObject", 20u },
    { 0x00eau, "NtSetInformationJobObject", 16u },
    { 0x00ebu, "NtSetInformationKey", 16u },
    { 0x00ecu, "NtSetInformationToken", 16u },
    { 0x00edu, "NtSetInformationVirtualMemory", 24u },
    { 0x00eeu, "NtSetIntervalProfile", 8u },
    { 0x00efu, "NtSetIoCompletion", 20u },
    { 0x00f0u, "NtSetIoCompletionEx", 24u },
    { 0x00f1u, "NtSetLdtEntries", 24u },
    { 0x00f2u, "NtSetSecurityObject", 12u },
    { 0x00f3u, "NtSetSystemInformation", 12u },
    { 0x00f4u, "NtSetSystemTime", 8u },
    { 0x00f5u, "NtSetThreadExecutionState", 8u },
    { 0x00f6u, "NtSetTimerResolution", 12u },
    { 0x00f7u, "NtSetVolumeInformationFile", 20u },
    { 0x00f8u, "NtShutdownSystem", 4u },
    { 0x00f9u, "NtSignalAndWaitForSingleObject", 16u },
    { 0x00fau, "NtSuspendProcess", 4u },
    { 0x00fbu, "NtSuspendThread", 8u },
    { 0x00fcu, "NtSystemDebugControl", 24u },
    { 0x00fdu, "NtTerminateJobObject", 8u },
    { 0x00feu, "NtTestAlert", 0u },
    { 0x00ffu, "NtTraceControl", 24u },
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
