# Initial GDI and splash contracts

The first GDI package is a portable, owner-supplied model for the exact splash
path reached by the Pinball host tracer. It is not a general GDI implementation
and it does not present pixels on PS5. `PwGdi` owns fixed-capacity DC and surface
tables plus a caller-provided pixel arena; no core operation allocates host
memory or stores a host pointer in a guest handle.

## Implemented surface

- Window DCs belong to one HWND and must be returned with the same HWND through
  `ReleaseDC`. Memory DCs record their compatible source and are destroyed only
  by `DeleteDC`.
- Compatible and resource bitmaps are typed objects. A bitmap can be selected
  into only one memory DC at a time and cannot be deleted while selected.
- Named `RT_BITMAP` loading accepts the source-confirmed uncompressed 8-bit DIB
  shape and converts palette indices into deterministic BGRA32 backing storage.
  PE resource-name comparison is ASCII case-insensitive, matching the observed
  lower-case request for an upper-case resource name.
- `GetObjectA` writes the exact 24-byte PE32 bitmap record used by the caller.
  `GetDeviceCaps` exposes a deterministic true-color/`RC_BITBLT` profile;
  `GetLayout`/`SetLayout` cover the observed LTR/RTL bit.
- `BitBlt` implements only `SRCCOPY` and `BLACKNESS`, with destination/source
  clipping and overlap-safe row copies. Empty clipped rectangles succeed
  without touching memory; unsupported raster operations stop explicitly.
- The true-color palette path accepts a null palette as a no-op. A non-null
  value for which no owned palette exists returns an invalid-handle failure and
  leaves the DC unchanged. This matters because the exact executable's splash
  object carries residual heap bytes in that field on this branch; accepting
  the value as a real palette would fabricate ownership.

Adjacent User32 support covers desktop/window geometry, `MoveWindow`,
`ShowWindow(SW_SHOWNA)`, focus, `GetWindowLongA`, synchronous `UpdateWindow`,
and the 64-byte PE32 `PAINTSTRUCT` lifecycle. `UpdateWindow` enters the original
WndProc for `WM_PAINT` and does not clear invalidation until the callback returns.
The x86 translator also gained `CDQ`, preserving guest flags.

## Ownership and failure rules

All guest-visible handles are 32-bit tokens. Capacity checks, pixel-range
checks and ABI return-frame validation occur before mutation. Failed selection,
deletion, resize, malformed DIB conversion and truncated guest frames preserve
the prior ownership state. Deleted surface ranges are zeroed before first-fit
reuse. `pw_gdi_validate` checks handle kinds, DC-to-surface links, selection
counts, arena bounds and non-overlap. `pw_gdi_reset` clears every object, every
pixel and the handle sequence.

Synthetic core and ABI suites cover ownership mismatches, invalid handles,
selection exclusivity, deletion while selected, capacity and pixel exhaustion,
clipping, raster copies, DIB validation/conversion, zeroed range reuse,
transactional truncated calls and complete reset. The tracer emits both live
GDI counts and a post-reset cleanup record.

## Sanitized exact-binary evidence

A bounded local run of the privately owned, hash-identified executable reaches
the public-PDB-verified application entry and then:

- retires 37,925 translated instructions;
- completes 241 adapter calls across 67 distinct DLL/API pairs;
- records 3,807 DBT dispatches, 3,469 cache hits, 338 misses/publications and
  107,008 emitted bytes in generation 1;
- completes splash bitmap construction, synchronous `WM_PAINT`, `BLACKNESS`
  clearing, centered `SRCCOPY`, DC release and `UpdateWindow` return;
- reports a valid live model with two DCs, three surfaces, one bitmap and
  16,872,960 owned pixel bytes;
- resets to zero DCs, surfaces, bitmaps and pixel bytes with validation intact.

Keyboard discovery, main-window setup, logical palette creation and the nested
WaveMix helper-window callback now also complete. The next classified stop is
`winmm!waveOutGetNumDevs`. This is host integration
evidence only: it is not a visible-window, gameplay, PS5 execution or hardware
presentation claim. Private binaries, resource bytes, decompiler output and raw
captures remain outside the repository.
