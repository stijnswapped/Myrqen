# ADR 010: Application-level envelope encryption for report bodies

Status: Accepted.

Context: report bodies carry customer security findings and code snippets. Storage-provider encryption alone means the object store sees plaintext.

Decision: encrypt every report body with AES-256-GCM before it reaches any storage driver. The envelope is `version | iv | authTag | ciphertext`, and the object key is bound in as associated data. Server-side encryption is still requested from S3-compatible stores as a second layer.

Consequence: a leaked bucket yields ciphertext, and a blob cannot be replayed under another report's key. The key is a deployment secret (`REPORT_ENCRYPTION_KEY`) and must move to a KMS before production; losing it makes stored reports unreadable, which is documented in the deployment notes.
