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
           "pe_entry_rva=0x%08x stub_id=0x%08x\n",
           entry_module, entry_symbol, report.entry_rva, report.entry_eip,
           report.entry_pe_rva, report.stub_syscall_id);
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
    printf("kind=host-wine-cleanup modules=%u mappings=%u translations=%u "
           "status=%s\n", report.cleanup_modules, report.cleanup_mappings,
           report.cleanup_translations, pw_result_name(report.status));
    printf("kind=host-wine-verdict accepted=%d stop=%s entry_id=0x%08x "
           "syscall=0x%08x retired=%llu\n",
           status == PW_OK && pw_wine_stop_is_acceptance(report.stop),
           pw_wine_stop_name(report.stop), report.stub_syscall_id,
           report.observed_syscall_id, (unsigned long long)report.retired);
    /* A classified stop is evidence, never a compatibility claim. */
    return status == PW_OK && pw_wine_stop_is_acceptance(report.stop) ? 0 : 1;
}
