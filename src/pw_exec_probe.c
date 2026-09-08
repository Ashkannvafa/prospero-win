/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_exec_probe.h"
#include "pw_win64_call.h"
#include <string.h>

int pw_exec_probe(const PwVmBackend *backend, PwExecProbe *report)
{
    static const uint8_t constant[] = {0xb8,42,0,0,0,0xc3};
    static const uint8_t alignment[] = {0x48,0x89,0xe0,0x83,0xe0,15,0xc3};
    /* a + 2b + 3c + 5d + 7e + 11f, using all four home slots and two
     * stack arguments. See test_pw_win64.c for the compiler ABI reference. */
    static const uint8_t weighted[] = {
        0x48,0x89,0x4c,0x24,8, 0x48,0x89,0x54,0x24,16,
        0x4c,0x89,0x44,0x24,24, 0x4c,0x89,0x4c,0x24,32,
        0x48,0x8b,0x44,0x24,8,
        0x48,0x6b,0x54,0x24,16,2, 0x48,0x01,0xd0,
        0x48,0x6b,0x54,0x24,24,3, 0x48,0x01,0xd0,
        0x48,0x6b,0x54,0x24,32,5, 0x48,0x01,0xd0,
        0x48,0x6b,0x54,0x24,40,7, 0x48,0x01,0xd0,
        0x48,0x6b,0x54,0x24,48,11, 0x48,0x01,0xd0, 0xc3
    };
    PwVmRegion region = {0};
    uint64_t args[6] = {2,3,5,7,11,13};
    int status;
    if (!report || !pw_vm_backend_valid(backend) || !backend->protect ||
        !(backend->capabilities & PW_VM_CAP_PROTECT))
        return PW_ERR_PRECONDITION;
    memset(report, 0, sizeof(*report));
    status = backend->reserve(backend->context, 256, backend->page_bytes, &region);
    if (status != PW_OK)
        return status;
    status = backend->commit(backend->context, &region, 0, 256,
                              PW_PROT_READ | PW_PROT_WRITE);
    if (status == PW_OK) {
        uint8_t *p = region.write_base;
        memcpy(p, constant, sizeof(constant));
        memcpy(p + 32, alignment, sizeof(alignment));
        memcpy(p + 64, weighted, sizeof(weighted));
        status = backend->protect(backend->context, &region, 0, region.bytes,
                                  PW_PROT_READ | PW_PROT_EXEC);
    }
    if (status == PW_OK) {
        const uintptr_t entry = (uintptr_t)region.exec_base;
        report->sealed = 1;
        report->constant = pw_win64_call6(entry, args);
        report->alignment = pw_win64_call6(entry + 32, args);
        report->weighted = pw_win64_call6(entry + 64, args);
        args[0] = 0x100000002ull;
        report->high = pw_win64_call6(entry + 64, args);
        if (report->constant != 42 || report->alignment != 8 ||
            report->weighted != 278 || report->high != 0x100000116ull)
            status = PW_ERR_STATE;
    }
    const int release = backend->release(backend->context, &region);
    report->released = release == PW_OK;
    return status == PW_OK ? release : status;
}
