# Core freeze

`src/p2r/` stays behavior-identical unless three things exist together: a broken invariant, a failing test that becomes a passing regression test, and a sentence in `SPEC.md`.

`assurance/` is not part of the protocol. It must not be imported by `src/p2r/`.

Out of V1, even if a note asks for them: a quarantine status inside the registry, an execution cache that grants authority, payments, consensus, a second dispatch path.

`sentinel/` may store `QUARANTINED` in `.sentinel/`. That word is not a core status and it does not gate `execute`. The sentinel must not be imported by `src/p2r/`. Its pin is `sentinel/pin.py` copied into `.sentinel/frozen.json`, not the manifest inside the commit it watches.

The same boundary is stated in `assurance/BOUNDARY.md`.
