/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Fault injection under the virtual-memory calls.
 *
 * The two calls that map and release guest memory own host state - backend
 * mappings, the dispatcher's declared regions, the run's accounting and the
 * guest's own output variables - and a handler that changes some of it before
 * a later step fails would leave the run half-mutated. The output spans are
 * preflighted in tests/test_pw_wine_gate_bridge.c; this test injects the
 * failures of the *backend* steps themselves (reserve, commit, release) and
 * exhausts the run's NT-region budget, and each case asserts that everything
 * the call would have changed is exactly what it was.
 *
 * The backend is a thin double around the real one: it forwards every call and
 * counts them, and fails the one step a case asks for. Nothing here needs Wine
 * or a second virtual-memory implementation.
 */
#include "pe_fixture.h"
#include "pw_unhandled_call.h"

#include "../src/pw_module_name.h"
#include "../src/pw_guest_process.h"
#include "../src/pw_vm_posix.h"
#include "../src/pw_wine_gate.h"
#include "../src/pw_wine_runner.h"

#include <assert.h>
#include <string.h>

/* The run's own workspace; two of these are independent. */
static PwWineRunner test_runner;

enum {
    TEXT_RVA = 0x1000,
    DATA_RVA = 0x2000,
    IMAGE_BASE = 0x11000000,
    SLOT_RVA = DATA_RVA,                    /* __wine_syscall_dispatcher */
    BASE_SLOT_RVA = DATA_RVA + 4,           /* *BaseAddress */
    SIZE_SLOT_RVA = DATA_RVA + 8,           /* *RegionSize */
    ALLOC_STATUS_RVA = DATA_RVA + 12,
    FREE_STATUS_RVA = DATA_RVA + 16,
    LAST_STATUS_RVA = DATA_RVA + 20,
    THUNK_RVA = TEXT_RVA + 0x200,
    STUB_ALLOC_RVA = TEXT_RVA + 0x210,      /* NtAllocateVirtualMemory, 0x18 */
    STUB_FREE_RVA = TEXT_RVA + 0x220,       /* NtFreeVirtualMemory, 0x1e */
    STUB_STOP_RVA = TEXT_RVA + 0x230,       /* no handler */
    CALLER_RVA = TEXT_RVA,
    ALLOCATION_SIZE = 0x4000,
    LOOP_SIZE = 0x1000,
    /* One iteration past the regions a run may own, so the last one is the
     * allocation the budget refuses. */
    LOOP_COUNT = PW_WINE_GATE_MAX_CALL_REGIONS,
};

enum TestMode {
    MODE_RESERVE_FAIL = 1,
    MODE_COMMIT_FAIL = 2,
    MODE_RELEASE_FAIL = 3,
    MODE_CAPACITY = 4,
    /* Teardown failure: every release the gate performs outside the guest's
     * heap window. The fixture reaches the engine and guest-process setup, so
     * one run exposes every pending-owner class in the gate report. */
    MODE_CLEANUP_FAIL = 5,
};

static uint8_t image[64 * 1024];
static uint8_t text[1024];
static uint32_t text_bytes;
static uint8_t data[32];
static PeFixtureReloc relocs[32];
static uint32_t reloc_count;

static void emit_byte(uint8_t value)
{
    assert(text_bytes < sizeof(text));
    text[text_bytes++] = value;
}

static void emit_u32(uint32_t value)
{
    emit_byte((uint8_t)(value & 0xffu));
    emit_byte((uint8_t)((value >> 8) & 0xffu));
    emit_byte((uint8_t)((value >> 16) & 0xffu));
    emit_byte((uint8_t)((value >> 24) & 0xffu));
}

static void emit_absolute(uint32_t rva)
{
    assert(reloc_count < sizeof(relocs) / sizeof(relocs[0]));
    relocs[reloc_count].rva = TEXT_RVA + text_bytes;
    relocs[reloc_count].type = PE_RELOC_HIGHLOW;
    reloc_count++;
    emit_u32(IMAGE_BASE + rva);
}

static void emit_push_absolute(uint32_t rva)
{
    emit_byte(0x68);
    emit_absolute(rva);
}

static void emit_push_imm8(uint8_t value)
{
    emit_byte(0x6a);
    emit_byte(value);
}

static void emit_push_imm32(uint32_t value)
{
    emit_byte(0x68);
    emit_u32(value);
}

static void emit_call(uint32_t target_rva)
{
    const uint32_t next = TEXT_RVA + text_bytes + 5u;

    emit_byte(0xe8);
    emit_u32(target_rva - next);
}

static void emit_store_eax(uint32_t rva)
{
    emit_byte(0xa3);
    emit_absolute(rva);
}

static void emit_store_imm32(uint32_t rva, uint32_t value)
{
    emit_byte(0xc7);
    emit_byte(0x05);
    emit_absolute(rva);
    emit_u32(value);
}

static void emit_stub(uint32_t index, uint32_t id, uint16_t arg_bytes)
{
    while (text_bytes < (uint32_t)index - TEXT_RVA)
        emit_byte(0x90);
    emit_byte(0xb8);
    emit_u32(id);
    emit_byte(0xba);
    emit_absolute(THUNK_RVA);
    emit_byte(0xff); emit_byte(0xd2);
    emit_byte(0xc2);
    emit_byte((uint8_t)(arg_bytes & 0xffu));
    emit_byte((uint8_t)((arg_bytes >> 8) & 0xffu));
    emit_byte(0x90);
}

/* NtAllocateVirtualMemory(process, &base, 0, &size, MEM_COMMIT, PAGE_READWRITE) */
static void emit_allocate(uint32_t status_rva)
{
    emit_push_imm8(0x04);
    emit_push_imm32(0x1000u);
    emit_push_absolute(SIZE_SLOT_RVA);
    emit_push_imm8(0x00);
    emit_push_absolute(BASE_SLOT_RVA);
    emit_push_imm8(0xff);
    emit_call(STUB_ALLOC_RVA);
    emit_store_eax(status_rva);
}

/* NtFreeVirtualMemory(process, &base, &size, MEM_RELEASE) */
static void emit_release(uint32_t status_rva)
{
    emit_store_imm32(SIZE_SLOT_RVA, 0u);
    emit_push_imm32(0x8000u);
    emit_push_absolute(SIZE_SLOT_RVA);
    emit_push_absolute(BASE_SLOT_RVA);
    emit_push_imm8(0xff);
    emit_call(STUB_FREE_RVA);
    emit_store_eax(status_rva);
}

/*
 * A call with no handler stops the run, and its arguments are the status the
 * run observed and the two output variables as the guest can still read them:
 * a call that failed must not have written either of them.
 */
/* The stop carries exactly the two arguments the unhandled call takes, so the
 * transcript after the run ends holds the status the last call answered with
 * and the size the guest read back out of its own slot. */
static void emit_stop_with(uint32_t status_rva)
{
    emit_byte(0xa1);
    emit_absolute(SIZE_SLOT_RVA);
    emit_byte(0x50);
    emit_byte(0xa1);
    emit_absolute(status_rva);
    emit_byte(0x50);
    emit_call(STUB_STOP_RVA);
}

static size_t build_module(enum TestMode mode)
{
    PeFixtureSpec spec;

    text_bytes = 0u;
    reloc_count = 0u;
    memset(data, 0, sizeof(data));
    /* The guest pre-fills *RegionSize with the block it wants. */
    memcpy(data + (SIZE_SLOT_RVA - DATA_RVA), &(uint32_t){ ALLOCATION_SIZE },
           4u);

    if (mode == MODE_CAPACITY) {
        /*
         * Exhaust the run's NT-region budget: each iteration asks for a fresh
         * block, and the allocation past the budget must be refused before the
         * backend is touched and must not be counted.
         */
        size_t loop_start;

        emit_byte(0xb9);                       /* mov ecx, LOOP_COUNT */
        emit_u32(LOOP_COUNT);
        loop_start = text_bytes;
        emit_store_imm32(SIZE_SLOT_RVA, LOOP_SIZE);
        emit_store_imm32(BASE_SLOT_RVA, 0u);
        emit_allocate(ALLOC_STATUS_RVA);
        emit_byte(0x49);                       /* dec ecx */
        emit_byte(0x75);                       /* jnz loop_start */
        emit_byte((uint8_t)(int8_t)((int)loop_start -
                                    (int)(text_bytes + 1u)));
        emit_stop_with(ALLOC_STATUS_RVA);
    } else {
        emit_allocate(ALLOC_STATUS_RVA);
        if (mode == MODE_RELEASE_FAIL)
            emit_release(FREE_STATUS_RVA);
        emit_stop_with(mode == MODE_RELEASE_FAIL ? FREE_STATUS_RVA
                                                 : ALLOC_STATUS_RVA);
    }

    while (text_bytes < THUNK_RVA - TEXT_RVA)
        emit_byte(0x90);
    emit_byte(0xff); emit_byte(0x25);
    emit_absolute(SLOT_RVA);
    emit_stub(STUB_ALLOC_RVA, 0x0018u, 24u);
    emit_stub(STUB_FREE_RVA, 0x001eu, 16u);
    emit_stub(STUB_STOP_RVA, PW_TEST_UNHANDLED_CALL_ID,
              PW_TEST_UNHANDLED_CALL_ARGS);
    emit_byte(0xc3);

    memset(&spec, 0, sizeof(spec));
    spec.pe32plus = 0;
    spec.dll = 1;
    spec.image_base = IMAGE_BASE;
    spec.dll_characteristics = PE_DLLCHAR_DYNAMIC_BASE | PE_DLLCHAR_NX_COMPAT;
    spec.entry_point = CALLER_RVA;
    spec.section_count = 2u;
    spec.sections[0].name = ".text";
    spec.sections[0].characteristics =
        PE_SCN_CNT_CODE | PE_SCN_MEM_READ | PE_SCN_MEM_EXECUTE;
    spec.sections[0].data = text;
    spec.sections[0].data_bytes = text_bytes;
    spec.sections[1].name = ".data";
    spec.sections[1].characteristics =
        PE_SCN_CNT_INITIALIZED_DATA | PE_SCN_MEM_READ | PE_SCN_MEM_WRITE;
    spec.sections[1].data = data;
    spec.sections[1].data_bytes = (uint32_t)sizeof(data);
    spec.export_base = 1u;
    spec.export_module_name = "ntdll.dll";
    spec.export_count = 2u;
    spec.exports[0].name = "__wine_syscall_dispatcher";
    spec.exports[0].ordinal = 1u;
    spec.exports[0].rva = SLOT_RVA;
    spec.exports[1].name = "TestEntry";
    spec.exports[1].ordinal = 2u;
    spec.exports[1].rva = CALLER_RVA;
    spec.reloc_count = reloc_count;
    for (uint32_t index = 0; index < reloc_count; ++index)
        spec.relocs[index] = relocs[index];
    return pe_fixture_build(image, sizeof(image), &spec);
}

/*
 * The backend double: it forwards every call to the real one and fails the
 * step a case injects, counting each so the rollback is observable.
 *
 * It keeps its state in a file-scope instance rather than in the vtable's
 * `context`, because the gate's low-address wrapper *replaces* that field with
 * a pointer to its own struct (it has to: the wrapper is what turns a
 * heap/section reservation into a low-address one). A backend that assumed its
 * context survived would be reading the wrapper as its own state. The gate
 * allows one instance per process today; that contract is documented, and
 * moving it into an owned context is part of the pending gate extraction.
 */
typedef struct FaultBackend {
    const PwVmBackend *real;
    unsigned fail_on;
    /* Only the calls that belong to the guest's own heap window are counted:
     * the gate's module and thread/process mappings go through the same vtable
     * and would otherwise blur what the call under test did. */
    unsigned heap_reserves;
    unsigned heap_reserve_ok;
    unsigned heap_commits;
    unsigned heap_release_ok;
    unsigned heap_release_failed;
    unsigned released_heap;
    unsigned cleanup_releases;      /* releases outside the guest heap window */
    unsigned cleanup_release_failed;
} FaultBackend;

static FaultBackend faults;

/*
 * The injected failures must apply to the *guest's* calls, not to the gate's
 * own mappings of the runtime modules and its thread/process pages: a backend
 * that cannot map the modules at all never reaches the call under test. The
 * guest's allocations come from the gate's heap window, which is where these
 * filters point.
 */
static int in_heap_window(uint64_t address)
{
    return address >= PW_WINE_GATE_HEAP_BASE && address < PW_WINE_GATE_HEAP_LIMIT;
}

static int fault_reserve_at(void *context, uint64_t address, size_t bytes,
                            size_t alignment, PwVmRegion *out)
{
    if (!in_heap_window(address))
        return faults.real->reserve_at(faults.real->context, address, bytes,
                                       alignment, out);
    faults.heap_reserves++;
    if (faults.fail_on == MODE_RESERVE_FAIL)
        return PW_ERR_VM;
    if (faults.real->reserve_at(faults.real->context, address, bytes,
                                alignment, out) != PW_OK)
        return PW_ERR_VM;
    faults.heap_reserve_ok++;
    return PW_OK;
    (void)context;
}

static int fault_reserve(void *context, size_t bytes, size_t alignment,
                         PwVmRegion *out)
{
    (void)context;
    return faults.real->reserve(faults.real->context, bytes, alignment, out);
}

static int fault_commit(void *context, const PwVmRegion *region, size_t offset,
                        size_t bytes, unsigned protection)
{
    (void)context;
    if (in_heap_window((uint64_t)(uintptr_t)region->exec_base)) {
        faults.heap_commits++;
        if (faults.fail_on == MODE_COMMIT_FAIL)
            return PW_ERR_VM;
    }
    return faults.real->commit(faults.real->context, region, offset, bytes,
                               protection);
}

static int fault_release(void *context, PwVmRegion *region)
{
    (void)context;
    if (in_heap_window((uint64_t)(uintptr_t)region->exec_base)) {
        if (faults.fail_on == MODE_RELEASE_FAIL && faults.released_heap == 0u) {
            faults.released_heap = 1u;  /* the guest's own release */
            faults.heap_release_failed++;
            return PW_ERR_VM;
        }
        if (faults.real->release(faults.real->context, region) == PW_OK)
            faults.heap_release_ok++;
        return PW_OK;
    }
    /*
     * Outside the heap window this is a teardown release - a module image, the
     * engine's own region, a process page or a call region the run registered
     * - and this mode fails every one of them so the run's cleanup verdict and
     * its ownership bookkeeping can be checked rather than inferred from
     * counts.
     */
    faults.cleanup_releases++;
    if (faults.fail_on == MODE_CLEANUP_FAIL) {
        faults.cleanup_release_failed++;
        return PW_ERR_VM;
    }
    return faults.real->release(faults.real->context, region);
}

static int fault_protect(void *context, const PwVmRegion *region, size_t offset,
                         size_t bytes, unsigned protection)
{
    (void)context;
    return faults.real->protect(faults.real->context, region, offset, bytes,
                                protection);
}

static PwFileSpan span;

static int fake_provider_open(void *context, const char *canonical_name,
                              PwFileSpan *out)
{
    (void)context;
    if (!pw_module_name_equal(canonical_name, "ntdll.dll"))
        return PW_ERR_NOT_FOUND;
    *out = span;
    return PW_OK;
}

static void fake_provider_close(void *context, PwFileSpan *closed)
{
    (void)context;
    (void)closed;
}

static int fake_provider_namespace(void *context, PwFileNamespace file_namespace,
                                   const char *canonical_name, PwFileSpan *out)
{
    (void)file_namespace;
    return fake_provider_open(context, canonical_name, out);
}

/* One run of one mode, optionally with a backend failure injected: returns the
 * report and the backend's counters so the caller can compare them. */
typedef struct CaseResult {
    PwWineGateReport report;
    unsigned heap_reserves;
    unsigned heap_reserve_ok;
    unsigned heap_commits;
    unsigned heap_release_ok;
    unsigned heap_release_failed;
    unsigned cleanup_releases;
    unsigned cleanup_release_failed;
    int status;
} CaseResult;

static CaseResult run_case(enum TestMode mode, int inject)
{
    const PwFileProvider provider = {
        .context = NULL, .open = fake_provider_open,
        .close = fake_provider_close, .open_namespace = fake_provider_namespace,
    };
    const char *modules[] = {"ntdll.dll"};
    PwWineGateConfig config;
    CaseResult result;
    PwVmBackend vm;
    PwVmBackend wrapped;
    size_t size;

    memset(&result, 0, sizeof(result));
    assert(pw_vm_posix_backend(&vm) == PW_OK);
    memset(&faults, 0, sizeof(faults));
    faults.real = &vm;
    faults.fail_on = inject ? (unsigned)mode : 0u;
    wrapped = (PwVmBackend){
        .context = NULL,
        .capabilities = vm.capabilities,
        .page_bytes = vm.page_bytes,
        .reserve = fault_reserve,
        .commit = fault_commit,
        .protect = fault_protect,
        .release = fault_release,
        .reserve_at = fault_reserve_at,
    };
    span.handle = NULL;
    span.path[0] = '\0';
    size = build_module(mode);
    assert(size != 0u);
    span.bytes = image;
    span.size = size;

    memset(&config, 0, sizeof(config));
    pw_wine_runner_init(&test_runner);
    config.runner = &test_runner;
    config.provider = &provider;
    config.backend = &wrapped;
    config.root_module = "ntdll.dll";
    config.entry_module = "ntdll.dll";
    config.entry_symbol = "TestEntry";
    config.modules[0] = modules[0];
    config.module_count = 1u;
    config.bridge_calls = 1u;

    result.status = pw_wine_gate_run(&config, &result.report);
    result.heap_reserves = faults.heap_reserves;
    result.heap_reserve_ok = faults.heap_reserve_ok;
    result.heap_commits = faults.heap_commits;
    result.heap_release_ok = faults.heap_release_ok;
    result.heap_release_failed = faults.heap_release_failed;
    result.cleanup_releases = faults.cleanup_releases;
    result.cleanup_release_failed = faults.cleanup_release_failed;
    return result;
}

int main(void)
{
    /* The backend's reserve fails. */
    {
        const CaseResult injected = run_case(MODE_RESERVE_FAIL, 1);

        assert(injected.status == PW_ERR_UNSUPPORTED);
        assert(injected.report.stop == PW_WINE_STOP_UNIX_CALL_UNIMPLEMENTED);
        assert(injected.report.allocations == 0u);
        assert(injected.report.call_regions == 1u);   /* only the parameters */
        assert(injected.report.allocated_bytes == 0u);
        assert(injected.heap_reserves >= 1u);   /* the whole heap scan refused */
        assert(injected.heap_reserve_ok == 0u);
        assert(injected.heap_commits == 0u);
        assert(injected.heap_release_ok == 0u);
        /* No backend mapping is left behind by the refused allocation. */
        assert(injected.heap_reserve_ok - injected.heap_release_ok == 0);
        /* The guest's own output variables keep the values it wrote. */
        {
            const PwUnixCallRecord *last = &injected.report.calls.sequence[
                injected.report.calls.records - 1u];

            assert(last->id == PW_TEST_UNHANDLED_CALL_ID);
            assert(last->args[0] == PW_NT_CONFLICTING_ADDRESSES);
            assert(last->args[1] == ALLOCATION_SIZE);
        }
    }
    /* The backend's commit fails: the reservation is given straight back. */
    {
        const CaseResult control = run_case(MODE_COMMIT_FAIL, 0);
        const CaseResult injected = run_case(MODE_COMMIT_FAIL, 1);

        assert(control.report.allocations == 1u);
        assert(control.report.allocated_bytes == ALLOCATION_SIZE);
        assert(injected.status == PW_ERR_UNSUPPORTED);
        assert(injected.report.allocations == 0u);
        assert(injected.report.call_regions == 1u);
        assert(injected.report.allocated_bytes == 0u);
        assert(injected.heap_reserves == 1u && injected.heap_commits == 1u);
        assert(injected.heap_release_failed == 0u);
        /* The failed commit is rolled back: the reservation the backend made
         * is given back, so no mapping is left live. The control releases its
         * one live block at cleanup, so both end with none. */
        assert(control.heap_reserve_ok == 1u && control.heap_release_ok == 1u);
        assert(injected.heap_reserve_ok == 1u && injected.heap_release_ok == 1u);
        assert(control.heap_reserve_ok - control.heap_release_ok == 0);
        assert(injected.heap_reserve_ok - injected.heap_release_ok == 0);
        {
            const PwUnixCallRecord *last = &injected.report.calls.sequence[
                injected.report.calls.records - 1u];

            assert(last->args[0] == PW_NT_INVALID_PARAMETER);
            assert(last->args[1] == ALLOCATION_SIZE);
        }
    }
    /* The backend's release fails: the block stays live and accounted for. */
    {
        const CaseResult control = run_case(MODE_RELEASE_FAIL, 0);
        const CaseResult injected = run_case(MODE_RELEASE_FAIL, 1);

        /* The control releases the guest's block successfully. */
        assert(control.report.allocations == 1u);
        assert(control.report.call_regions == 1u);
        assert(control.report.allocated_bytes == 0u);
        assert(injected.status == PW_ERR_UNSUPPORTED);
        assert(injected.report.allocations == 1u);
        assert(injected.report.call_regions == 2u);
        assert(injected.report.allocated_bytes == ALLOCATION_SIZE);
        assert(injected.heap_reserves == 1u && injected.heap_commits == 1u);
        assert(injected.heap_release_failed == 1u);   /* the guest's release */
        assert(injected.heap_release_ok == 1u);       /* cleanup's, later */
        assert(control.heap_release_failed == 0u && control.heap_release_ok == 1u);
        assert(injected.heap_reserve_ok - injected.heap_release_ok == 0);
        /* The failed call wrote neither output: the guest still reads the
         * size it wrote itself (zero) out of its own slot. */
        {
            const PwUnixCallRecord *last = &injected.report.calls.sequence[
                injected.report.calls.records - 1u];

            assert(last->args[0] == PW_NT_INVALID_PARAMETER);
            assert(last->args[1] == 0u);
        }
    }
    /* NT-region budget: the process-parameters block the run did not allocate
     * takes the first of the regions the run may own, the blocks up to the
     * budget stay live and accounted for, and the allocation past it is
     * refused before any backend step. That this, and not the dispatcher's
     * declared-region table, is what refuses is a property of the table being
     * sized for the whole module graph plus this budget, which
     * src/pw_wine_gate.c asserts at compile time. */
    {
        const CaseResult injected = run_case(MODE_CAPACITY, 0);

        assert(injected.status == PW_ERR_UNSUPPORTED);
        assert(injected.report.allocations == LOOP_COUNT - 1u);
        assert(injected.report.call_regions == PW_WINE_GATE_MAX_CALL_REGIONS);
        assert(injected.report.allocated_bytes == (LOOP_COUNT - 1u) * LOOP_SIZE);
        /* The refused allocation never reaches the backend, so it is neither
         * reserved, committed nor released; everything the run kept is
         * released at cleanup. */
        assert(injected.heap_reserves == LOOP_COUNT - 1u);
        assert(injected.heap_commits == LOOP_COUNT - 1u);
        assert(injected.heap_release_ok == LOOP_COUNT - 1u);
        assert(injected.heap_reserve_ok - injected.heap_release_ok == 0);
        {
            const PwUnixCallRecord *last = &injected.report.calls.sequence[
                injected.report.calls.records - 1u];

            assert(last->args[0] == PW_NT_INVALID_PARAMETER);
        }
    }
    /*
     * Teardown failures. The cleanup verdict has to come from what the
     * releases did, not from what the run mapped: a release that fails keeps
     * its owner so it can be retried, and the report has to say so.
     */
    /* Every teardown release fails: the run reports it, keeps the owner so it
     * can be retried, and still executed exactly what it executed before. */
    {
        const CaseResult control = run_case(MODE_CLEANUP_FAIL, 0);
        const CaseResult injected = run_case(MODE_CLEANUP_FAIL, 1);

        assert(control.report.cleanup_failures == 0u);
        assert(control.report.cleanup_modules_pending == 0u);
        assert(control.report.cleanup_modules == control.report.module_count);
        assert(injected.cleanup_releases >= 1u);
        assert(injected.cleanup_release_failed == injected.cleanup_releases);
        assert(injected.report.cleanup_failures == 4u);
        assert(injected.report.cleanup_translations == 0u);
        assert(injected.report.cleanup_translations_pending == 1u);
        assert(injected.report.cleanup_process_pages_pending == 3u);
        assert(injected.report.cleanup_call_regions_pending == 1u);
        assert(injected.report.cleanup_modules == 0u);
        assert(injected.report.cleanup_modules_pending ==
               injected.report.module_count);
        /* A cleanup failure is not a different guest execution, but it is a
         * failed gate: callers must not accept a run that leaked an owner. */
        assert(injected.report.stop == control.report.stop);
        assert(injected.report.retired == control.report.retired);
        assert(control.status == PW_ERR_UNSUPPORTED);
        assert(injected.status == PW_ERR_VM);
        assert(injected.report.status == PW_ERR_VM);
    }
    return 0;
}
