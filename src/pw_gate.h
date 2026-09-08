/*
 * Gate report: the structured evidence one load produces.
 *
 * The runtime does not format telemetry ad hoc. It runs the loader, fills
 * this report, and the PS5 adapter emits each line verbatim through
 * `ps5log/1`. Keeping the record vocabulary here makes it host-testable and
 * lets tools/validate_pe_map_evidence.py re-derive the load-order property
 * from the transcript instead of trusting the runtime's own conclusion.
 *
 * Formatting uses local bounded helpers rather than snprintf: on this
 * firmware every imported libc symbol is a liability until a hardware smoke
 * test has accepted it, and a number formatter is not worth that risk.
 */
#ifndef PROSPERO_WIN_GATE_H
#define PROSPERO_WIN_GATE_H

#include "pw_compat32.h"
#include "pw_loader.h"

enum {
    PW_GATE_LINE_MAX = 480,
    PW_GATE_MAX_LINES = 256,
};

/*
 * Records are handed to the sink the moment they are complete, not after
 * the run finishes. A crash mid-gate otherwise takes every record with it,
 * which is exactly what happened on the first hardware run: the transcript
 * ended at the last marker main() had emitted itself and said nothing about
 * how far the loader had got.
 */
typedef void (*PwGateSink)(const char *line, void *context);

typedef struct PwGateReport {
    char lines[PW_GATE_MAX_LINES][PW_GATE_LINE_MAX];
    uint32_t line_count;
    uint32_t truncated;      /* lines that did not fit the buffer */
    int result;              /* the loader's result, echoed for the caller */
    PwGateSink sink;         /* optional; called per completed record */
    void *sink_context;
} PwGateReport;

typedef struct PwGateRequest {
    const void *root_bytes;
    size_t root_size;
    const char *root_name;
    const char *provider_path;   /* provenance only, may be NULL */
    PwGateSink sink;             /* survives the report's own reset */
    void *sink_context;
} PwGateRequest;

/*
 * Loads the root and its dependency chain, then records PW_BOOT, one
 * PW_MODULE per module, one PW_DEP per edge, one PW_ORDER per load
 * position, one PW_PROTECT per mapped module and a final PW_EXIT.
 *
 * Returns the loader's result. The report is filled either way: a failed
 * load still produces PW_BOOT and PW_EXIT, because a run that fails must be
 * as attributable as one that passes.
 */
int pw_gate_run(PwGateReport *report, PwLoader *loader,
                const PwFileProvider *provider, const PwVmBackend *backend,
                const PwGateRequest *request);

/*
 * Appends the gate 0.2a record. Emitted whatever the outcome: a refusal is
 * the measurement, so it has to be as attributable as a success.
 */
int pw_gate_compat32(PwGateReport *report, const PwCompat32Report *probe);

#endif
