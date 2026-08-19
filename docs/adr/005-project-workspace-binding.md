# ADR 005: Explicit repository workspace binding

Status: Accepted.

Decision: personal binding is local-only; team binding is safe-to-commit project metadata. A committed team binding is authoritative and cannot silently fall back to Personal. Unbound repos choose workspace on first scan.
