# Licence: an open decision

This repository does not yet carry a licence file, deliberately. Under the
laboratory's isolation rule a project receives its final name, title id,
licence and remote only at the publication gate, and for this project the
choice has a consequence worth deciding on purpose rather than by copying
the neighbouring repositories.

## Why it is not simply GPL-3.0

`ps5-agc-gears` and `ps5-xash3d` are GPL-3.0-or-later, which suits them:
they are applications, and Xash3D's own upstream licence points that way.

prospero-win is a different kind of artifact. It is a compatibility layer
whose entire purpose is to be combined, at run time, with proprietary
third-party code — the game executable and vendor DLLs it manually maps, and
whose imports it will bind to its own implementations. A strong copyleft on
the layer itself invites exactly the argument that has followed Wine for
decades, which is why Wine relicensed from GPL to LGPL in 2002.

## Candidates

| Licence | Effect here |
| --- | --- |
| **LGPL-3.0-or-later** (suggested) | Copyleft on the layer, and the layer stays usable by the proprietary programs it exists to run. The Wine precedent is directly on point |
| MIT or Apache-2.0 | Maximum reuse, including in closed forks of the layer itself |
| GPL-3.0-or-later | Consistent with the sibling repositories, but the least comfortable fit for a compatibility layer |

## Until it is decided

The code is the author's own work (see `NOTICE.md`) and is unpublished. No
licence is claimed or granted by this file. The decision is the owner's, and
it should be made before the first public push rather than after, because
relicensing later requires the agreement of every contributor by then.
