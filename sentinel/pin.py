"""Bootstrap pin for the frozen core.

This is not read from the commit being watched. A commit can change
src/p2r and tests/integration/core_manifest.json together. It cannot
move this constant without changing the sentinel that emits the proof.
"""

FROZEN_CORE_DIGEST = "33f1f479026ed81def4907ca0296b3af5edab0c5ac2e2da1808deb3f89473ce6"
FROZEN_AT = "c4d8053c67289d0e497d2d400f1cb7d71795f77f"
