# Fix workflow

## Actions

### Suggest fix
Shows remediation guidance and a generated coding-agent prompt. No source changes.

### Apply fix
Only from an active local host-agent context. The user explicitly invokes/approves it. The host coding agent edits the local repository. Cloud dashboard may provide a Copy prompt to fix button but must not silently remote-control the local machine.

### Apply and verify
After explicit action:
1. apply code/config change;
2. run relevant unit/integration checks;
3. rerun targeted Myrqen validation;
4. mark fixed only on successful security verification;
5. record revision and changed-file summary locally and, if synced, update report state through explicit sync/live rules.

## Copy prompt contents

Include:
- finding ID/title/severity/verification;
- concise root cause;
- affected file/route/component;
- relevant sanitized code/evidence;
- remediation constraints;
- regression/security tests to add/run;
- instruction to preserve unrelated behavior;
- instruction to rerun Myrqen targeted verification.

Never include raw secrets.

## Report history

Preserve original finding evidence and remediation result. Do not overwrite history to make a fixed issue appear never to have existed.
