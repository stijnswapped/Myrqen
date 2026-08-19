# ADR 003: Per-scan opt-in cloud sync

Status: Accepted.

Decision: check quota and ask whether to sync before each scan. If yes, create live report immediately. If no/quota blocked, no live cloud stream. Later sync is explicit `myrqen sync REPORT_ID`, never automatic.
