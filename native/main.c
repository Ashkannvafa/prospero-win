/*
 * prospero-win Phase 0 gate 1: make the console's Zen 2 cores read and
 * understand a raw Windows executable.
 *
 * The title stages a PE image and its third-party dependencies under a
 * read-only directory, manually maps every one of them, verifies the
 * mapping byte by byte and reports the whole graph through ps5log/1.
 * Nothing is executed: this gate proves parsing, placement, zero fill,
 * relocation, page protection and recursive dependency resolution, and
 * nothing more. Whether the mapped code can run is a later, separate
 * question, answered in docs/EXECUTION_MODEL.md.
 *
 * Teardown follows the laboratory's measured rule: after the report and the
 * BYE the runtime calls _exit(0) instead of returning from main(), because
 * the CRT exit path leaves the shell showing a failure dialog on FW 12.02.
 */
#include "../src/pw_gate.h"
#include "../src/pw_vm_posix.h"
#include "pw_file_ps5.h"
#include "ps5log/ps5log.h"

#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

#define PW_TITLE_ID "PPSA99995"
#define PW_APP_NAME "prospero-win"

#ifndef PW_STAGE_DIR
#define PW_STAGE_DIR "/app0/win"
#endif
#ifndef PW_ROOT_MODULE
#define PW_ROOT_MODULE "sample.exe"
#endif

static PwFilePs5 files;
static PwFileProvider provider;
static PwVmBackend backend;

static uint64_t now_ns(void)
{
    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        return 0u;
    return (uint64_t)value.tv_sec * 1000000000ull + (uint64_t)value.tv_nsec;
}

/*
 * The loader registry and the gate report are far too large for the libc
 * heap, which is about 8 MiB here and cannot be grown from a title. Both
 * come from an anonymous mapping, the measured route for large allocations.
 */
static void *reserve_scratch(size_t bytes)
{
    void *base = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    return base == MAP_FAILED ? NULL : base;
}

int main(int argc, char **argv)
{
    const uint64_t boot_token = now_ns();
    const char *stage_dir = PW_STAGE_DIR;
    const char *root_name = PW_ROOT_MODULE;
    ps5log_config log_config;
    const char *log_path = NULL;
    PwFilePs5Smoke smoke;
    PwGateRequest request;
    PwGateReport *report;
    PwLoader *loader;
    PwFileSpan root;
    int config_result;
    int log_result;
    int status;

    (void)argc;
    (void)argv;

    ps5log_config_defaults(&log_config);
    config_result = ps5log_load_config(ps5log_default_conf_paths,
                                        ps5log_default_conf_path_count,
                                        &log_config, &log_path);
    log_result = config_result == 0
        ? ps5log_init(&log_config, PW_TITLE_ID, PW_APP_NAME, boot_token)
        : config_result;

    loader = reserve_scratch(sizeof(*loader));
    report = reserve_scratch(sizeof(*report));
    if (!loader || !report) {
        PS5LOG_LOG("PW_ABORT stage=scratch loader=%d report=%d",
                   loader != NULL, report != NULL);
        ps5log_close("pe-map-scratch-unavailable");
        _exit(0);
    }

    PS5LOG_LOG("PW_BEGIN schema=1 slice=pe-map title=%s stage=%s root=%s "
               "log_config=%d log_init=%d loader_bytes=%llu",
               PW_TITLE_ID, stage_dir, root_name, config_result, log_result,
               (unsigned long long)sizeof(*loader));

    status = pw_file_ps5_init(&files, stage_dir);
    if (status != PW_OK) {
        PS5LOG_LOG("PW_ABORT stage=provider status=%s",
                   pw_result_name(status));
        ps5log_close("pe-map-provider-rejected");
        _exit(0);
    }

    /*
     * Platform pre-flight before any parsing: prove the exact calls the
     * provider depends on, on this firmware, against the staged bytes.
     */
    status = pw_file_ps5_smoke(&files, root_name, &smoke);
    PS5LOG_LOG("PW_FS_SMOKE status=%s open=%d stat=%d read=%d seek=%d "
               "close=%d size=%lld magic=0x%02x%02x is_pe=%d",
               pw_result_name(status), smoke.open_result, smoke.stat_result,
               smoke.read_result, smoke.seek_result, smoke.close_result,
               smoke.size, smoke.first_bytes[0], smoke.first_bytes[1],
               smoke.is_pe);
    if (status != PW_OK) {
        ps5log_close("pe-map-filesystem-unusable");
        _exit(0);
    }

    (void)pw_file_ps5_provider(&files, &provider);
    status = pw_vm_posix_backend(&backend);
    if (status != PW_OK) {
        PS5LOG_LOG("PW_ABORT stage=backend status=%s",
                   pw_result_name(status));
        ps5log_close("pe-map-backend-unavailable");
        _exit(0);
    }

    status = provider.open(provider.context, root_name, &root);
    if (status != PW_OK) {
        PS5LOG_LOG("PW_ABORT stage=root status=%s name=%s",
                   pw_result_name(status), root_name);
        ps5log_close("pe-map-root-unreadable");
        _exit(0);
    }

    memset(&request, 0, sizeof(request));
    request.root_bytes = root.bytes;
    request.root_size = root.size;
    request.root_name = root_name;
    request.provider_path = stage_dir;

    status = pw_gate_run(report, loader, &provider, &backend, &request);
    for (uint32_t index = 0; index < report->line_count; ++index)
        PS5LOG_LOG("%s", report->lines[index]);

    provider.close(provider.context, &root);
    PS5LOG_LOG("PW_FILES opens=%u closes=%u failures=%u bytes=%llu",
               files.opens, files.closes, files.failures,
               (unsigned long long)files.bytes_read);

    /*
     * Every span the provider handed out has been closed and every
     * reservation released before the channel closes, so the transcript
     * ends on a state the operator can trust.
     */
    ps5log_close(status == PW_OK ? "pe-map-complete" : "pe-map-failed");
    _exit(0);
}
