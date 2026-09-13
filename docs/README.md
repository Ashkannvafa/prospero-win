# Documentation

Everything in this directory is intended for the public prospero-win
repository. Raw captures, telemetry transcripts, reverse-engineering
workspaces, proprietary inputs, agent reports and day-to-day laboratory goals
are deliberately kept outside the standalone project.

## Start here

- [Architecture](ARCHITECTURE.md): component boundaries, memory ownership and
  failure rules.
- [Wine integration](WINE_INTEGRATION.md): Windows subsystem boundary, CPU
  execution choices and the DXVK-to-ps5-vulkan graphics path.
- [Wine foundation ledger](WINE_FOUNDATION.json): machine-readable component
  status, dependencies and exit criteria.
- [Development](DEVELOPMENT.md): required gates and native build workflow.
- [Compatibility roadmap](ROADMAP.md): public milestones and current scope.
- [Hardware validation](HARDWARE_VALIDATION.md): accepted claims and evidence
  rules.
- [Execution model](EXECUTION_MODEL.md) and
  [x86 execution](X86_EXECUTION.md): ABI and DBT design.
- [Guest ABI](GUEST_ABI.md): callbacks and reusable Win32-facing services.
- [Telemetry](TELEMETRY.md): the `ps5log/1` vocabulary and validators.

## Compatibility work

- [Import plan](IMPORT_PLAN.md): static discovery and runtime-module bring-up.
- [Wine reuse audit](WINE_REUSE_AUDIT.md): pinned-source findings and the
  transition away from title-specific direct wrappers.
- [GDI](GDI.md)
- [First playable target](PINBALL_TARGET.md)
- [PE mapping](PE_MAPPING_PHASE0.md)
- [32-bit compatibility investigation](COMPAT32_PHASE0A.md)

The Pinball source oracle and instruction-coverage files contain only
sanitized provenance and aggregate data. They contain no executable bytes,
assembly listing or proprietary resource.
