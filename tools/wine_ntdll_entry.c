/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Host runner for the bounded Wine ntdll entry gate.
 *
 * It loads a staged i386 Wine runtime, binds the real module graph, enters
 * one exported ntdll function through the IA-32 DBT and stops at the
 * versioned Unix-call boundary. The private input is a build artifact, never
 * a file in this repository.
 *
 *   wine_ntdll_entry --runtime .deps/wine-runtime
 *
 * Every line it prints is `kind=host-wine-...` telemetry consumed by
 * tools/validate_wine_ntdll_evidence.py.
 */
#include "../src/pw_file_posix.h"
#include "../src/pw_vm_posix.h"
#include "../src/pw_wine_gate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static PwWineGateReport report;

static void trace_step(void *context, const PwX86State *state)
{
    (void)context;
    printf("kind=host-wine-step eip=0x%08x esp=0x%08x eax=0x%08x "
           "ebx=0x%08x ecx=0x%08x edx=0x%08x esi=0x%08x edi=0x%08x "
           "ebp=0x%08x fs=0x%08x\n", state->eip, state->gpr[4], state->gpr[0],
           state->gpr[3], state->gpr[1], state->gpr[2], state->gpr[6],
           state->gpr[7], state->gpr[5], state->fs_base);
    /* Flush per step: a mode that faults must still leave its trace. */
    fflush(stdout);
}

static const char *argument_value(int argc, char **argv, const char *name,
                                  const char *fallback)
{
    for (int index = 1; index + 1 < argc; ++index)
        if (strcmp(argv[index], name) == 0)
            return argv[index + 1];
    return fallback;
}

static unsigned argument_number(int argc, char **argv, const char *name,
                                unsigned fallback)
{
    const char *text = argument_value(argc, argv, name, NULL);

    if (!text)
        return fallback;
    return (unsigned)strtoul(text, NULL, 0);
}

static void print_module(const PwWineModuleRecord *module)
{
    printf("kind=host-wine-module name=%s sha256=%s size=%u machine=0x%04x "
           "base=0x%08x image_bytes=%u loaded=%u runtime=%u imports=%u tls=%u "
           "path=%s\n",
           module->name, module->sha256, module->size, module->machine,
           module->base, module->image_bytes, module->loaded, module->runtime,
           module->imports, module->tls_present, module->path);
}

int main(int argc, char **argv)
{
    PwWineGateConfig config;
    PwFilePosix files;
    PwFileProvider provider;
    PwVmBackend vm;
    /* The provider opens a canonical module name inside one directory, so
     * --runtime is the staged PE library, not the distribution root. */
    const char *runtime = argument_value(argc, argv, "--runtime",
                                         ".deps/wine-runtime/lib/i386-windows");
    const char *entry_module = argument_value(argc, argv, "--entry-module",
                                              "ntdll.dll");
    const char *entry_symbol = argument_value(argc, argv, "--entry-symbol",
                                              "NtClose");
    const char *root = argument_value(argc, argv, "--root", "kernelbase.dll");
    const char *dlls = argument_value(argc, argv, "--modules",
                                      "ntdll.dll,kernelbase.dll");
    int status;

    if (!runtime) {
        fprintf(stderr, "usage: wine_ntdll_entry [--runtime lib/i386-windows] "
                        "[--entry-module ntdll.dll] [--entry-symbol NtClose] "
                        "[--root kernelbase.dll] [--budget N]\n");
        return 2;
    }
    if (pw_file_posix_init(&files, runtime) != PW_OK ||
        pw_file_posix_set_runtime_directory(&files, runtime) != PW_OK ||
        pw_file_posix_provider(&files, &provider) != PW_OK ||
        pw_vm_posix_backend(&vm) != PW_OK) {
        fprintf(stderr, "cannot initialise the runtime provider\n");
        return 2;
    }
    memset(&config, 0, sizeof(config));
    config.provider = &provider;
    config.backend = &vm;
    config.root_module = root;
    config.entry_module = entry_module;
    config.entry_symbol = entry_symbol;
    config.step_budget = argument_number(argc, argv, "--budget", 0u);
    config.trace = argument_value(argc, argv, "--trace", NULL) ? trace_step
                                                               : NULL;
    config.bridge_calls = (uint8_t)(argument_number(argc, argv, "--bridge", 0u) != 0u);
    config.call_budget = argument_number(argc, argv, "--call-budget", 0u);
    {
        const char *modes = argument_value(argc, argv, "--modes", NULL);

        if (modes) {
            /* chaining,residency,lazy-flags: 0 or 1 each. */
            unsigned values[3] = {1u, 1u, 1u};

            for (unsigned index = 0; index < 3u && *modes; ++index) {
                values[index] = (unsigned)strtoul(modes, NULL, 0) != 0u;
                const char *comma = strchr(modes, ',');
                modes = comma ? comma + 1 : modes + strlen(modes);
            }
            config.chaining = (uint8_t)values[0];
            config.residency = (uint8_t)values[1];
            config.lazy_flags = (uint8_t)values[2];
            config.modes_set = 1u;
        }
    }
    {
        char *copy = malloc(strlen(dlls) + 1u);

        if (!copy)
            return 2;
        memcpy(copy, dlls, strlen(dlls) + 1u);
        for (char *name = strtok(copy, ","); name != NULL;
             name = strtok(NULL, ",")) {
            if (config.module_count >= PW_WINE_GATE_MAX_MODULES)
                break;
            config.modules[config.module_count++] = name;
        }
        printf("kind=host-wine-gate runtime=%s root=%s entry=%s!%s "
               "modules=%u\n", runtime, root, entry_module, entry_symbol,
               config.module_count);
        status = pw_wine_gate_run(&config, &report);
        free(copy);
    }
    for (uint32_t index = 0; index < report.module_count; ++index)
        print_module(&report.modules[index]);
    printf("kind=host-wine-bind modules=%u functions=%u data=%u failures=%u\n",
           report.bound_modules, report.bound_functions, report.bound_data,
           report.bind_failures);
    printf("kind=host-wine-tls modules=%u\n", report.tls_modules);
    printf("kind=host-wine-boundary slot_rva=0x%08x slot_va=0x%08x "
           "thunks=%u thunk_rva=0x%08x thunk_va=0x%08x\n",
           report.boundary_slot_rva, report.boundary_slot_va,
           report.boundary_count, report.boundary_thunk_rva,
           report.boundary_thunk_va);
    printf("kind=host-wine-entry module=%s symbol=%s rva=0x%08x eip=0x%08x "
           "pe_entry_rva=0x%08x stub_id=0x%08x kind=%s\n",
           entry_module, entry_symbol, report.entry_rva, report.entry_eip,
           report.entry_pe_rva, report.stub_syscall_id,
           report.stub_syscall_id != 0u ? "stub" : "initialization");
    printf("kind=host-wine-call return_eip=0x%08x in_module=%u caller_rva=0x%08x "
           "caller_id=0x%08x observed=0x%08x\n",
           report.boundary_return_eip, report.boundary_return_in_module,
           report.caller_stub_rva, report.caller_stub_id,
           report.observed_syscall_id);
    printf("kind=host-wine-modes chaining=%u residency=%u lazy_flags=%u\n",
           report.chaining, report.residency, report.lazy_flags);
    printf("kind=host-wine-run first_eip=0x%08x last_eip=0x%08x "
           "retired=%llu dispatches=%llu blocks=%llu bytes=%llu "
           "stop_address=0x%08x stop=%s syscall=0x%08x host_calls=%llu\n",
           report.first_eip, report.last_eip,
           (unsigned long long)report.retired,
           (unsigned long long)report.dispatches,
           (unsigned long long)report.translated_blocks,
           (unsigned long long)report.translated_bytes,
           report.stop_address, pw_wine_stop_name(report.stop),
           report.observed_syscall_id, (unsigned long long)report.host_calls);
    if (report.stop == PW_WINE_STOP_MEMORY_BOUNDS)
        printf("kind=host-wine-fault address=0x%08x width=%u write=%u\n",
               report.fault_address, report.fault_width, report.fault_write);
    /*
     * The cleanup verdict is about releasing what this run mapped and
     * translated; the run's own result is already carried by the stop kind,
     * because a bridged run that meets an unimplemented instruction family
     * stops honestly without being a leak.
     */
    printf("kind=host-wine-cleanup modules=%u mappings=%u translations=%u "
           "status=%s gate_status=%s\n", report.cleanup_modules,
           report.cleanup_mappings, report.cleanup_translations,
           (report.cleanup_modules == report.module_count &&
            report.cleanup_translations >= 1u &&
            report.cleanup_mappings >= report.module_count) ? "ok"
                                                           : "incomplete",
           pw_result_name(report.status));
    if (config.bridge_calls) {
        printf("kind=host-wine-calls serviced=%u handled=%llu unimplemented=%llu "
               "unknown=%llu rejected=%llu allocations=%u allocated_bytes=%u "
               "regions=%u\n", report.calls_serviced,
               (unsigned long long)report.calls.handled,
               (unsigned long long)report.calls.unimplemented,
               (unsigned long long)report.calls.unknown,
               (unsigned long long)report.calls.rejected, report.allocations,
               report.allocated_bytes, report.call_regions);
        for (uint32_t index = 0; index < report.calls.records; ++index) {
            const PwUnixCallRecord *record = &report.calls.sequence[index];

            printf("kind=host-wine-call-seq index=%u id=0x%08x name=%s "
                   "args=%u stub_return=0x%08x return=0x%08x status=0x%08x "
                   "outcome=%s argument=%u\n", index, record->id,
                   record->name[0] ? record->name : "unknown",
                   record->arg_bytes, record->stub_return_pc,
                   record->return_pc, record->status,
                   pw_unix_call_outcome_name(record->outcome),
                   record->argument_index);
            printf("kind=host-wine-call-args index=%u a0=0x%08x a1=0x%08x "
                   "a2=0x%08x a3=0x%08x a4=0x%08x a5=0x%08x esp=0x%08x\n",
                   index, record->args[0], record->args[1], record->args[2],
                   record->args[3], record->args[4], record->args[5],
                   record->esp);
        }
    }
    printf("kind=host-wine-verdict accepted=%d stop=%s entry_id=0x%08x "
           "syscall=0x%08x retired=%llu\n",
           status == PW_OK && pw_wine_stop_is_acceptance(report.stop),
           pw_wine_stop_name(report.stop), report.stub_syscall_id,
           report.observed_syscall_id, (unsigned long long)report.retired);
    /* A classified stop is evidence, never a compatibility claim. */
    return status == PW_OK && pw_wine_stop_is_acceptance(report.stop) ? 0 : 1;
}
