/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_gate.h"

#include <string.h>

typedef struct Line {
    char *bytes;
    size_t capacity;
    size_t length;
    int overflow;
} Line;

static void line_begin(Line *line, char *bytes, size_t capacity)
{
    line->bytes = bytes;
    line->capacity = capacity;
    line->length = 0u;
    line->overflow = 0;
    if (capacity != 0u)
        bytes[0] = '\0';
}

static void put_text(Line *line, const char *text)
{
    size_t index = 0;

    if (!text)
        text = "";
    while (text[index] != '\0') {
        if (line->length + 1u >= line->capacity) {
            line->overflow = 1;
            return;
        }
        line->bytes[line->length++] = text[index++];
    }
    line->bytes[line->length] = '\0';
}

static void put_u64(Line *line, uint64_t value)
{
    char digits[20];
    size_t count = 0;

    do {
        digits[count++] = (char)('0' + (int)(value % 10u));
        value /= 10u;
    } while (value != 0u && count < sizeof(digits));
    while (count != 0u) {
        if (line->length + 1u >= line->capacity) {
            line->overflow = 1;
            return;
        }
        line->bytes[line->length++] = digits[--count];
    }
    line->bytes[line->length] = '\0';
}

static void put_hex(Line *line, uint64_t value)
{
    static const char table[] = "0123456789abcdef";
    char digits[16];
    size_t count = 0;

    put_text(line, "0x");
    do {
        digits[count++] = table[value & 0xfu];
        value >>= 4;
    } while (value != 0u && count < sizeof(digits));
    while (count != 0u) {
        if (line->length + 1u >= line->capacity) {
            line->overflow = 1;
            return;
        }
        line->bytes[line->length++] = digits[--count];
    }
    line->bytes[line->length] = '\0';
}

static void field_text(Line *line, const char *key, const char *value)
{
    put_text(line, " ");
    put_text(line, key);
    put_text(line, "=");
    put_text(line, value);
}

static void field_u64(Line *line, const char *key, uint64_t value)
{
    put_text(line, " ");
    put_text(line, key);
    put_text(line, "=");
    put_u64(line, value);
}

static void field_hex(Line *line, const char *key, uint64_t value)
{
    put_text(line, " ");
    put_text(line, key);
    put_text(line, "=");
    put_hex(line, value);
}

/* Reserves the next report line, or NULL when the report is full. */
static Line *next_line(PwGateReport *report, Line *line, const char *marker)
{
    if (report->line_count >= PW_GATE_MAX_LINES) {
        ++report->truncated;
        return NULL;
    }
    line_begin(line, report->lines[report->line_count], PW_GATE_LINE_MAX);
    put_text(line, marker);
    return line;
}

static void commit_line(PwGateReport *report, const Line *line)
{
    if (line->overflow) {
        ++report->truncated;
        return;
    }
    /* Emitted before the counter advances, so a fault inside the sink
     * cannot leave a half-published record counted as complete. */
    if (report->sink)
        report->sink(report->lines[report->line_count], report->sink_context);
    ++report->line_count;
}

static void record_boot(PwGateReport *report, const PwGateRequest *request,
                        const PwVmBackend *backend)
{
    Line line;

    if (!next_line(report, &line, "PW_BOOT"))
        return;
    field_u64(&line, "schema", 1u);
    field_text(&line, "slice", "pe-map");
    field_text(&line, "root", request->root_name);
    field_text(&line, "provider",
               request->provider_path ? request->provider_path : "none");
    field_u64(&line, "root_bytes", request->root_size);
    field_u64(&line, "page_bytes", backend->page_bytes);
    field_u64(&line, "aliased_exec",
              (backend->capabilities & PW_VM_CAP_ALIASED_EXEC) != 0u ? 1u : 0u);
    field_u64(&line, "modules_cap", PW_LOADER_MAX_MODULES);
    commit_line(report, &line);
}

static void record_module(PwGateReport *report, const PwLoader *loader,
                          uint32_t index)
{
    const PwModule *module = pw_loader_module(loader, index);
    Line line;

    if (!module || !next_line(report, &line, "PW_MODULE"))
        return;
    field_u64(&line, "index", index);
    field_text(&line, "name", module->name);
    field_text(&line, "kind", pw_module_kind_name(module->kind));
    field_text(&line, "machine", module->kind == PW_MODULE_HOST
                                     ? "none"
                                     : pe_image_machine_name(&module->image));
    field_u64(&line, "native", module->machine_native);
    field_u64(&line, "dll", module->is_dll);
    field_u64(&line, "depth", module->depth);
    field_u64(&line, "deps", module->dependency_count);
    field_u64(&line, "mapped", module->mapped_ok);
    field_u64(&line, "sections", module->layout.section_count);
    field_u64(&line, "image_bytes", module->mapped.image_bytes);
    field_hex(&line, "base", module->mapped.actual_base);
    field_hex(&line, "preferred", module->mapped.preferred_base);
    field_u64(&line, "reloc_blocks", module->mapped.relocs.blocks);
    field_u64(&line, "reloc_applied", module->mapped.relocs.applied);
    field_u64(&line, "imports", module->import_symbols);
    field_u64(&line, "zero_bytes", module->layout.zero_bytes);
    field_u64(&line, "verify_sections", module->verify.sections_checked);
    field_u64(&line, "verify_compared", module->verify.bytes_compared);
    field_u64(&line, "verify_mismatch", module->verify.raw_mismatches);
    field_u64(&line, "verify_zero_tail", module->verify.zero_tail_violations);
    field_u64(&line, "verify_alias", module->verify.alias_mismatches);
    field_u64(&line, "headers", module->verify.headers_present);
    field_hex(&line, "checksum", module->verify.checksum);
    commit_line(report, &line);
}

static void record_dependencies(PwGateReport *report, const PwLoader *loader,
                                uint32_t index)
{
    const PwModule *module = pw_loader_module(loader, index);

    if (!module)
        return;
    for (uint32_t edge = 0; edge < module->dependency_count; ++edge) {
        const PwModule *target =
            pw_loader_module(loader, module->dependencies[edge]);
        Line line;

        if (!target || !next_line(report, &line, "PW_DEP"))
            return;
        field_u64(&line, "index", index);
        field_text(&line, "name", module->name);
        field_u64(&line, "dep_index", module->dependencies[edge]);
        field_text(&line, "dep_name", target->name);
        field_text(&line, "dep_kind", pw_module_kind_name(target->kind));
        commit_line(report, &line);
    }
}

static void record_order(PwGateReport *report, const PwLoader *loader)
{
    for (uint32_t position = 0; position < loader->order_count; ++position) {
        const uint16_t index = loader->order[position];
        const PwModule *module = pw_loader_module(loader, index);
        Line line;

        if (!module || !next_line(report, &line, "PW_ORDER"))
            return;
        field_u64(&line, "position", position);
        field_u64(&line, "index", index);
        field_text(&line, "name", module->name);
        commit_line(report, &line);
    }
}

static void record_graph(PwGateReport *report, const PwLoader *loader)
{
    Line line;

    if (!next_line(report, &line, "PW_GRAPH"))
        return;
    field_u64(&line, "modules", loader->module_count);
    field_u64(&line, "local", loader->local_count);
    field_u64(&line, "host", loader->host_count);
    field_u64(&line, "cycles", loader->cycle_edges);
    field_u64(&line, "max_depth", loader->max_depth);
    field_u64(&line, "reserved_bytes", loader->reserved_bytes);
    field_u64(&line, "ordered", loader->order_count);
    field_text(&line, "machine",
               loader->machine == PE_MACHINE_AMD64 ? "amd64"
                   : (loader->machine == PE_MACHINE_I386 ? "i386" : "none"));
    commit_line(report, &line);
}

static void record_protection(PwGateReport *report, const PwLoader *loader)
{
    for (uint32_t index = 0; index < loader->module_count; ++index) {
        const PwModule *module = pw_loader_module(loader, index);
        Line line;

        if (!module || !module->mapped_ok)
            continue;
        if (!next_line(report, &line, "PW_PROTECT"))
            return;
        field_u64(&line, "index", index);
        field_text(&line, "name", module->name);
        field_u64(&line, "applied", module->mapped.protections_applied);
        field_u64(&line, "pages", module->mapped.protection.pages);
        field_u64(&line, "merged", module->mapped.protection.merged_pages);
        field_u64(&line, "wx", module->mapped.protection.wx_pages);
        field_u64(&line, "no_access", module->mapped.protection.no_access_pages);
        field_u64(&line, "calls", module->mapped.protection.protect_calls);
        commit_line(report, &line);
    }
}

static void record_exit(PwGateReport *report, uint32_t module_total,
                        int result, uint32_t mapped, uint32_t released,
                        const char *missing)
{
    Line line;

    if (!next_line(report, &line, "PW_EXIT"))
        return;
    field_u64(&line, "result", result == PW_OK ? 0u : (uint64_t)(-result));
    field_text(&line, "status", pw_result_name(result));
    field_u64(&line, "modules", module_total);
    field_u64(&line, "mapped", mapped);
    field_u64(&line, "released", released);
    field_text(&line, "missing", missing && missing[0] != '\0' ? missing
                                                               : "none");
    field_u64(&line, "truncated", report->truncated);
    commit_line(report, &line);
}

int pw_gate_compat32(PwGateReport *report, const PwCompat32Report *probe)
{
    Line line;

    if (!report || !probe)
        return PW_ERR_PRECONDITION;
    if (!next_line(report, &line, "PW_COMPAT32"))
        return PW_ERR_LIMIT;
    field_u64(&line, "schema", 1u);
    field_text(&line, "install", pw_result_name(probe->install_result));
    field_u64(&line, "install_errno", (uint64_t)(unsigned)probe->install_errno);
    field_u64(&line, "ldt_code", probe->ldt_code_index);
    field_u64(&line, "ldt_data", probe->ldt_data_index);
    field_hex(&line, "code_sel", probe->code_selector);
    field_hex(&line, "data_sel", probe->data_selector);
    field_hex(&line, "cs64", probe->cs64);
    field_hex(&line, "ds64", probe->ds64);
    field_text(&line, "reserve", pw_result_name(probe->reserve_result));
    field_hex(&line, "code_base", probe->code_base);
    field_hex(&line, "data_base", probe->data_base);
    field_text(&line, "build", pw_result_name(probe->build_result));
    field_text(&line, "seal", pw_result_name(probe->seal_result));
    field_u64(&line, "seal_errno", (uint64_t)(unsigned)probe->seal_errno);
    field_text(&line, "transfer", pw_result_name(probe->transfer_result));
    field_u64(&line, "attempted", probe->transfer_attempted);
    field_u64(&line, "returned", probe->transfer_returned);
    field_u64(&line, "result", probe->result_value);
    field_hex(&line, "cs_seen", probe->cs_seen);
    field_u64(&line, "expected", PW_COMPAT32_EXPECTED_RESULT);
    field_u64(&line, "proven", probe->compat32_proven);
    commit_line(report, &line);
    return PW_OK;
}

int pw_gate_run(PwGateReport *report, PwLoader *loader,
                const PwFileProvider *provider, const PwVmBackend *backend,
                const PwGateRequest *request)
{
    char missing[PW_MODULE_NAME_MAX + 1];
    uint32_t module_total = 0u;
    uint32_t mapped = 0u;
    uint32_t released = 0u;
    int status;
    int release_status;

    if (!report || !loader || !request || !request->root_bytes ||
        !request->root_name || !pw_file_provider_valid(provider) ||
        !pw_vm_backend_valid(backend))
        return PW_ERR_PRECONDITION;
    memset(report, 0, sizeof(*report));
    report->sink = request->sink;
    report->sink_context = request->sink_context;
    memset(missing, 0, sizeof(missing));

    record_boot(report, request, backend);
    status = pw_loader_init(loader, provider, backend);
    if (status != PW_OK) {
        /*
         * The registry was never initialised, so it must not be read or
         * released here: the run is reported from what is known instead.
         */
        record_exit(report, 0u, status, 0u, 0u, NULL);
        report->result = status;
        return status;
    }

    status = pw_loader_load(loader, request->root_bytes, request->root_size,
                             request->root_name);
    if (status == PW_OK) {
        for (uint32_t index = 0; index < loader->module_count; ++index) {
            record_module(report, loader, index);
            record_dependencies(report, loader, index);
            if (pw_loader_module(loader, index)->mapped_ok)
                ++mapped;
        }
        record_order(report, loader);
        record_graph(report, loader);
        status = pw_loader_finalize(loader);
        record_protection(report, loader);
    } else {
        memcpy(missing, loader->missing, sizeof(missing) - 1u);
    }

    /* The counts are captured before release, which zeroes the registry. */
    module_total = loader->module_count;
    release_status = pw_loader_release(loader);
    released = release_status == PW_OK ? mapped : 0u;
    if (status == PW_OK && release_status != PW_OK)
        status = release_status;
    record_exit(report, module_total, status, mapped, released, missing);
    report->result = status;
    return status;
}
