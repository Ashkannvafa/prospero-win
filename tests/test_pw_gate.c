#include "pe_fixture.h"

#include "../src/pw_gate.h"
#include "../src/pw_module_name.h"
#include "../src/pw_vm_posix.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

enum {
    MAX_FILES = 4,
    IMAGE_CAPACITY = 64 * 1024,
};

static uint8_t images[MAX_FILES][IMAGE_CAPACITY];
static size_t sizes[MAX_FILES];
static const char *names[MAX_FILES];
static uint32_t file_count;
static const uint8_t code[64] = {0x48, 0x31, 0xc0, 0xc3};

static PwLoader loader;
static PwGateReport report;

static int fake_open(void *context, const char *canonical_name,
                     PwFileSpan *out)
{
    (void)context;
    for (uint32_t index = 0; index < file_count; ++index) {
        if (!names[index] || !pw_module_name_equal(names[index],
                                                    canonical_name))
            continue;
        memset(out, 0, sizeof(*out));
        out->bytes = images[index];
        out->size = sizes[index];
        memcpy(out->path, "/app0/win", 10);
        return PW_OK;
    }
    return PW_ERR_NOT_FOUND;
}

static void fake_close(void *context, PwFileSpan *span)
{
    (void)context;
    span->bytes = NULL;
}

static PwFileProvider provider = {NULL, fake_open, fake_close};

static void add(const char *name, int dll, const char *const *imports,
                uint32_t import_count)
{
    PeFixtureSpec spec;
    const uint32_t slot = file_count;

    assert(slot < MAX_FILES);
    memset(&spec, 0, sizeof(spec));
    spec.pe32plus = 1;
    spec.dll = dll;
    spec.image_base = 0x180000000ull + (uint64_t)slot * 0x100000ull;
    spec.dll_characteristics = PE_DLLCHAR_DYNAMIC_BASE | PE_DLLCHAR_NX_COMPAT;
    spec.section_count = 2u;
    spec.sections[0].name = ".text";
    spec.sections[0].characteristics =
        PE_SCN_CNT_CODE | PE_SCN_MEM_READ | PE_SCN_MEM_EXECUTE;
    spec.sections[0].data = code;
    spec.sections[0].data_bytes = (uint32_t)sizeof(code);
    spec.sections[1].name = ".data";
    spec.sections[1].characteristics =
        PE_SCN_CNT_INITIALIZED_DATA | PE_SCN_MEM_READ | PE_SCN_MEM_WRITE;
    spec.sections[1].data = code;
    spec.sections[1].data_bytes = 32u;
    spec.entry_point = 0x1000u;
    spec.reloc_count = 1u;
    spec.relocs[0].rva = 0x2000u;
    spec.relocs[0].type = PE_RELOC_DIR64;
    for (uint32_t index = 0; index < import_count; ++index) {
        spec.imports[index].dll = imports[index];
        spec.imports[index].names[0] = "Entry";
    }
    spec.import_count = import_count;
    sizes[slot] = pe_fixture_build(images[slot], IMAGE_CAPACITY, &spec);
    assert(sizes[slot] != 0u);
    names[slot] = name;
    ++file_count;
}

static const char *find_line(const char *prefix, uint32_t occurrence)
{
    uint32_t seen = 0;

    for (uint32_t index = 0; index < report.line_count; ++index) {
        if (strncmp(report.lines[index], prefix, strlen(prefix)) != 0)
            continue;
        if (seen++ == occurrence)
            return report.lines[index];
    }
    return NULL;
}

static uint32_t count_lines(const char *prefix)
{
    uint32_t total = 0;

    for (uint32_t index = 0; index < report.line_count; ++index) {
        if (strncmp(report.lines[index], prefix, strlen(prefix)) == 0)
            ++total;
    }
    return total;
}

static void test_successful_gate_report(void)
{
    static const char *const root_imports[] = {"binkw32.dll", "KERNEL32.dll"};
    static const char *const bink_imports[] = {"msvcrt.dll"};
    PwVmBackend backend;
    PwGateRequest request;
    const char *line;

    file_count = 0u;
    add(NULL, 0, root_imports, 2u);          /* root, passed in directly */
    add("binkw32.dll", 1, bink_imports, 1u);

    assert(pw_vm_posix_backend(&backend) == PW_OK);
    memset(&request, 0, sizeof(request));
    request.root_bytes = images[0];
    request.root_size = sizes[0];
    request.root_name = "game.exe";
    request.provider_path = "/app0/win";

    assert(pw_gate_run(&report, &loader, &provider, &backend, &request) ==
           PW_OK);
    assert(report.result == PW_OK);
    assert(report.truncated == 0u);

    line = find_line("PW_BOOT", 0u);
    assert(line != NULL);
    assert(strstr(line, "schema=1") != NULL);
    assert(strstr(line, "slice=pe-map") != NULL);
    assert(strstr(line, "root=game.exe") != NULL);
    assert(strstr(line, "provider=/app0/win") != NULL);
    assert(strstr(line, "aliased_exec=0") != NULL);

    /* game.exe, binkw32.dll, kernel32.dll, msvcrt.dll */
    assert(count_lines("PW_MODULE") == 4u);
    line = find_line("PW_MODULE", 0u);
    assert(strstr(line, "index=0") != NULL);
    assert(strstr(line, "name=game.exe") != NULL);
    assert(strstr(line, "kind=root") != NULL);
    assert(strstr(line, "machine=amd64") != NULL);
    assert(strstr(line, "native=1") != NULL);
    assert(strstr(line, "mapped=1") != NULL);
    assert(strstr(line, "reloc_applied=1") != NULL);
    assert(strstr(line, "verify_mismatch=0") != NULL);
    assert(strstr(line, "verify_zero_tail=0") != NULL);
    assert(strstr(line, "verify_alias=0") != NULL);
    assert(strstr(line, "headers=1") != NULL);
    assert(strstr(line, "checksum=0x") != NULL);

    /* A host binding is reported as present but never mapped. */
    line = find_line("PW_MODULE", 2u);
    assert(strstr(line, "name=kernel32.dll") != NULL);
    assert(strstr(line, "kind=host") != NULL);
    assert(strstr(line, "machine=none") != NULL);
    assert(strstr(line, "mapped=0") != NULL);
    assert(strstr(line, "base=0x0") != NULL);

    /* Edges are emitted so a validator can re-derive the load order. */
    assert(count_lines("PW_DEP") == 3u);
    line = find_line("PW_DEP", 0u);
    assert(strstr(line, "index=0") != NULL);
    assert(strstr(line, "dep_name=binkw32.dll") != NULL);
    assert(strstr(line, "dep_kind=local") != NULL);

    assert(count_lines("PW_ORDER") == 4u);
    line = find_line("PW_ORDER", 3u);
    assert(strstr(line, "position=3") != NULL);
    assert(strstr(line, "name=game.exe") != NULL);

    line = find_line("PW_GRAPH", 0u);
    assert(strstr(line, "modules=4") != NULL);
    assert(strstr(line, "local=1") != NULL);
    assert(strstr(line, "host=2") != NULL);
    assert(strstr(line, "cycles=0") != NULL);
    assert(strstr(line, "machine=amd64") != NULL);
    assert(strstr(line, "ordered=4") != NULL);

    /* Only mapped modules have pages to protect. */
    assert(count_lines("PW_PROTECT") == 2u);
    line = find_line("PW_PROTECT", 0u);
    assert(strstr(line, "applied=1") != NULL);
    assert(strstr(line, "wx=0") != NULL);

    line = find_line("PW_EXIT", 0u);
    assert(strstr(line, "result=0") != NULL);
    assert(strstr(line, "status=ok") != NULL);
    assert(strstr(line, "modules=4") != NULL);
    assert(strstr(line, "mapped=2") != NULL);
    assert(strstr(line, "released=2") != NULL);
    assert(strstr(line, "missing=none") != NULL);
    assert(strstr(line, "truncated=0") != NULL);

    /* Every line fits the transport's record budget. */
    for (uint32_t index = 0; index < report.line_count; ++index)
        assert(strlen(report.lines[index]) < PW_GATE_LINE_MAX);
}

static void test_failed_gate_is_still_attributable(void)
{
    static const char *const root_imports[] = {"mss32.dll"};
    PwVmBackend backend;
    PwGateRequest request;
    const char *line;

    file_count = 0u;
    add(NULL, 0, root_imports, 1u);

    assert(pw_vm_posix_backend(&backend) == PW_OK);
    memset(&request, 0, sizeof(request));
    request.root_bytes = images[0];
    request.root_size = sizes[0];
    request.root_name = "game.exe";

    assert(pw_gate_run(&report, &loader, &provider, &backend, &request) ==
           PW_ERR_NOT_FOUND);
    /* A failing run must produce evidence too, naming what was missing. */
    assert(find_line("PW_BOOT", 0u) != NULL);
    assert(count_lines("PW_MODULE") == 0u);
    line = find_line("PW_EXIT", 0u);
    assert(line != NULL);
    assert(strstr(line, "status=not-found") != NULL);
    assert(strstr(line, "missing=mss32.dll") != NULL);
    assert(strstr(line, "mapped=0") != NULL);
    assert(strstr(line, "provider=none") == NULL);
    line = find_line("PW_BOOT", 0u);
    assert(strstr(line, "provider=none") != NULL);
}

static void test_preconditions(void)
{
    PwVmBackend backend;
    PwGateRequest request;

    assert(pw_vm_posix_backend(&backend) == PW_OK);
    memset(&request, 0, sizeof(request));
    request.root_bytes = images[0];
    request.root_size = sizes[0];
    request.root_name = "game.exe";

    assert(pw_gate_run(NULL, &loader, &provider, &backend, &request) ==
           PW_ERR_PRECONDITION);
    assert(pw_gate_run(&report, NULL, &provider, &backend, &request) ==
           PW_ERR_PRECONDITION);
    assert(pw_gate_run(&report, &loader, NULL, &backend, &request) ==
           PW_ERR_PRECONDITION);
    assert(pw_gate_run(&report, &loader, &provider, NULL, &request) ==
           PW_ERR_PRECONDITION);
    assert(pw_gate_run(&report, &loader, &provider, &backend, NULL) ==
           PW_ERR_PRECONDITION);
    request.root_name = NULL;
    assert(pw_gate_run(&report, &loader, &provider, &backend, &request) ==
           PW_ERR_PRECONDITION);
}

static void test_compat32_record(void)
{
    PwCompat32Report probe;
    const char *line;

    memset(&report, 0, sizeof(report));
    memset(&probe, 0, sizeof(probe));

    /* A refusal is a measurement and must still be reported in full. */
    probe.install_result = PW_ERR_UNSUPPORTED;
    probe.install_errno = 78;
    probe.cs64 = 0x0033u;
    assert(pw_gate_compat32(&report, &probe) == PW_OK);
    line = find_line("PW_COMPAT32", 0u);
    assert(line != NULL);
    assert(strstr(line, "install=unsupported") != NULL);
    assert(strstr(line, "install_errno=78") != NULL);
    assert(strstr(line, "attempted=0") != NULL);
    assert(strstr(line, "proven=0") != NULL);
    assert(strstr(line, "expected=3") != NULL);

    /* A proven round trip carries the selector it actually ran under. */
    memset(&report, 0, sizeof(report));
    probe.install_result = PW_OK;
    probe.install_errno = 0;
    probe.reserve_result = PW_OK;
    probe.build_result = PW_OK;
    probe.seal_result = PW_OK;
    probe.transfer_result = PW_OK;
    probe.ldt_index = 0u;
    probe.code_selector = 0x0007u;
    probe.data_selector = 0x000fu;
    probe.code_base = 0x20000000u;
    probe.data_base = 0x20001000u;
    probe.transfer_attempted = 1u;
    probe.transfer_returned = 1u;
    probe.result_value = PW_COMPAT32_EXPECTED_RESULT;
    probe.cs_seen = 0x0007u;
    probe.compat32_proven = 1u;
    assert(pw_gate_compat32(&report, &probe) == PW_OK);
    line = find_line("PW_COMPAT32", 0u);
    assert(strstr(line, "install=ok") != NULL);
    assert(strstr(line, "code_sel=0x7") != NULL);
    assert(strstr(line, "cs_seen=0x7") != NULL);
    assert(strstr(line, "result=3") != NULL);
    assert(strstr(line, "proven=1") != NULL);
    assert(strstr(line, "code_base=0x20000000") != NULL);
    assert(strlen(line) < PW_GATE_LINE_MAX);

    assert(pw_gate_compat32(NULL, &probe) == PW_ERR_PRECONDITION);
    assert(pw_gate_compat32(&report, NULL) == PW_ERR_PRECONDITION);
}

/* Emits the report so tests/test_validate_pe_map_evidence.py can consume it. */
static void emit_transcript(void)
{
    static const char *const root_imports[] = {"binkw32.dll", "KERNEL32.dll"};
    static const char *const bink_imports[] = {"msvcrt.dll"};
    PwVmBackend backend;
    PwGateRequest request;

    file_count = 0u;
    add(NULL, 0, root_imports, 2u);
    add("binkw32.dll", 1, bink_imports, 1u);
    assert(pw_vm_posix_backend(&backend) == PW_OK);
    memset(&request, 0, sizeof(request));
    request.root_bytes = images[0];
    request.root_size = sizes[0];
    request.root_name = "game.exe";
    request.provider_path = "/app0/win";
    assert(pw_gate_run(&report, &loader, &provider, &backend, &request) ==
           PW_OK);
    for (uint32_t index = 0; index < report.line_count; ++index)
        (void)printf("%s\n", report.lines[index]);
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--emit") == 0) {
        emit_transcript();
        return 0;
    }
    test_successful_gate_report();
    test_failed_gate_is_still_attributable();
    test_compat32_record();
    test_preconditions();
    return 0;
}
