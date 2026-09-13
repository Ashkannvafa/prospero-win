# Contributing

prospero-win favors reusable compatibility contracts over title-specific
patches. A change should explain which Windows or processor behavior it
implements, cite the relevant public reference, and include a focused
regression test.

## Before opening a change

```sh
make all
make sanitize
git diff --check
```

`make all` includes the fail-closed publication audit. New repository files
must be reviewed and added to `PUBLICATION_ALLOWLIST.txt`.

Do not submit proprietary executables, DLLs, shaders, SDK files, telemetry
transcripts, captures, private paths or secrets. Synthetic PE fixtures and
small original test programs are preferred.

Hardware claims require exact artifact identity plus structured
`ps5log/1` evidence. Screenshots and videos are useful supporting material
but do not establish execution, ownership or cleanup by themselves.

Keep pull requests focused. Describe current limitations explicitly and avoid
general compatibility or performance claims that the included evidence does
not establish.
