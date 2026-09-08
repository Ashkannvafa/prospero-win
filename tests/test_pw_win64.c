/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pe_fixture.h"
#include "../include/prospero_win_abi.h"
#include "../src/pw_map.h"
#include "../src/pw_vm_posix.h"
#include "../src/pw_win64_call.h"
#include "../src/pw_exec_probe.h"

#include <assert.h>
#include <string.h>

typedef uint64_t (PW_WIN64_ABI *GuestSix)(uint64_t, uint64_t, uint64_t,
                                        uint64_t, uint64_t, uint64_t);
typedef uint64_t (PW_WIN64_ABI *GuestLeaf)(void);
typedef double (PW_WIN64_ABI *GuestFloat)(double, double, double, double);
static uint8_t file[16384];
static PwVmBackend backend;
static PeImage image;
static PeLayout layout;
static PwMappedImage mapped;
static unsigned bridge_calls;
static GuestSix guest_callback;

/* A normal host-ABI function behind an explicitly Win64 entry point. */
static __attribute__((noinline)) uint64_t host_core(uint64_t a, uint64_t b, uint64_t c,
                          uint64_t d, uint64_t e, uint64_t f)
{
    ++bridge_calls;
    return a + 2*b + 3*c + 5*d + 7*e + 11*f;
}

static __attribute__((noinline)) uint64_t PW_WIN64_ABI host_bridge(uint64_t a, uint64_t b, uint64_t c,
                                        uint64_t d, uint64_t e, uint64_t f)
{
    return host_core(a, b, c, d, e, f);
}

static __attribute__((noinline)) uint64_t PW_WIN64_ABI callback_bridge(uint64_t a, uint64_t b,
                                            uint64_t c, uint64_t d,
                                            uint64_t e, uint64_t f)
{
    ++bridge_calls;
    return guest_callback(a, b, c, d, e, f) + 100;
}

static uintptr_t map_code(const uint8_t *code, size_t bytes)
{
    PeFixtureSpec spec;
    PwMapVerify verify;
    memset(&spec, 0, sizeof(spec));
    spec.pe32plus = 1;
    /* Low application memory is outside ASan's reserved shadow interval. */
    spec.image_base = 0x02000000ull;
    spec.section_count = 1;
    spec.sections[0].name = ".text";
    spec.sections[0].characteristics =
        PE_SCN_CNT_CODE | PE_SCN_MEM_READ | PE_SCN_MEM_EXECUTE;
    spec.sections[0].data = code;
    spec.sections[0].data_bytes = (uint32_t)bytes;
    spec.entry_point = 0x1000;
    size_t size = pe_fixture_build(file, sizeof(file), &spec);
    assert(size != 0);
    assert(pe_image_parse(&image, file, size) == PW_OK);
    assert(pe_layout_plan(&layout, &image) == PW_OK);
    assert(pw_map_image(&mapped, &image, &layout, &backend) == PW_OK);
    assert(pw_map_verify(&mapped, &image, &layout, &verify) == PW_OK);
    assert(verify.raw_mismatches == 0);
    assert(pw_map_finalize_protections(&mapped, &layout, &backend) == PW_OK);
    assert(mapped.protection.wx_pages == 0);
    return (uintptr_t)pw_map_exec_address(&mapped, layout.entry_point);
}

static void release_code(void)
{
    assert(pw_map_release(&mapped, &backend) == PW_OK);
}

int main(void)
{
    assert(pw_vm_posix_backend(&backend) == PW_OK);
    PwExecProbe probe;
    assert(pw_exec_probe(&backend, &probe) == PW_OK);
    assert(probe.constant == 42 && probe.alignment == 8);
    assert(probe.weighted == 278 && probe.high == 0x100000116ull);
    assert(probe.sealed == 1 && probe.released == 1);
    /* mov eax,42; ret */
    static const uint8_t constant[] = {0xb8,42,0,0,0,0xc3};
    assert(((GuestLeaf)map_code(constant, sizeof(constant)))() == 42);
    release_code();

    /* mov rax,rsp; and eax,15; ret: entry stack must be 8 modulo 16. */
    static const uint8_t alignment[] = {0x48,0x89,0xe0,0x83,0xe0,15,0xc3};
    assert(((GuestLeaf)map_code(alignment, sizeof(alignment)))() == 8);
    release_code();

    /* Write all four home slots, then recover them. Fifth/sixth arguments
     * live at rsp+40/rsp+48. Distinct weights catch register permutations.
     * rax = a + 2*b + 3*c + 5*d + 7*e + 11*f. */
    static const uint8_t six[] = {
        0x48,0x89,0x4c,0x24,8, 0x48,0x89,0x54,0x24,16,
        0x4c,0x89,0x44,0x24,24, 0x4c,0x89,0x4c,0x24,32,
        0x48,0x8b,0x44,0x24,8,
        0x48,0x6b,0x54,0x24,16,2, 0x48,0x01,0xd0,
        0x48,0x6b,0x54,0x24,24,3, 0x48,0x01,0xd0,
        0x48,0x6b,0x54,0x24,32,5, 0x48,0x01,0xd0,
        0x48,0x6b,0x54,0x24,40,7, 0x48,0x01,0xd0,
        0x48,0x6b,0x54,0x24,48,11, 0x48,0x01,0xd0, 0xc3
    };
    GuestSix function = (GuestSix)map_code(six, sizeof(six));
    const uint64_t arguments[6] = {2,3,5,7,11,13};
    assert(pw_win64_call6((uintptr_t)function, arguments) == 278);
    assert(function(2,3,5,7,11,13) == 278);
    assert(function(0x100000002ull,3,5,7,11,13) == 0x100000116ull);
    guest_callback = function;
    assert(callback_bridge(2,3,5,7,11,13) == 378);
    assert(bridge_calls == 1);
    release_code();
    guest_callback = NULL;

    /* addsd xmm0,xmm1; addsd xmm0,xmm2; addsd xmm0,xmm3; ret */
    static const uint8_t floats[] = {
        0xf2,0x0f,0x58,0xc1, 0xf2,0x0f,0x58,0xc2,
        0xf2,0x0f,0x58,0xc3, 0xc3
    };
    assert(((GuestFloat)map_code(floats, sizeof(floats)))(1.5,2.25,4.5,8.0)
           == 16.25);
    release_code();

    /* Tail jump preserves the caller-provided home/stack arguments while
     * crossing mapped guest -> ms_abi entry -> ordinary host C. */
    uint8_t tail[] = {0x48,0xb8,0,0,0,0,0,0,0,0,0xff,0xe0};
    const uint64_t target = (uint64_t)(uintptr_t)&host_bridge;
    memcpy(tail + 2, &target, sizeof(target));
    function = (GuestSix)map_code(tail, sizeof(tail));
    assert(function(2,3,5,7,11,13) == 278);
    assert(bridge_calls == 2);
    release_code();

    /* Full re-entry: mapped guest -> host callback bridge -> mapped guest.
     * Both routines share a live RX image until the outer call returns. */
    uint8_t roundtrip[256] = {0};
    const uint64_t callback_target = (uint64_t)(uintptr_t)&callback_bridge;
    memcpy(roundtrip, tail, sizeof(tail));
    memcpy(roundtrip + 2, &callback_target, sizeof(callback_target));
    memcpy(roundtrip + 32, six, sizeof(six));
    uintptr_t entry = map_code(roundtrip, sizeof(roundtrip));
    guest_callback = (GuestSix)(entry + 32);
    assert(((GuestSix)entry)(2,3,5,7,11,13) == 378);
    assert(bridge_calls == 3);
    assert(pw_win64_call6(entry, arguments) == 378);
    assert(bridge_calls == 4);
    guest_callback = NULL;
    release_code();
    return 0;
}
