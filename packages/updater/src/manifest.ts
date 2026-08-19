import crypto from "node:crypto";
import { validateUpdateManifest, formatIssues } from "@myrqen/contracts";

export interface UpdateArtifact {
  os: "darwin" | "windows" | "linux";
  arch: "x64" | "arm64";
  url: string;
  sha256: string;
  size: number;
}

export interface RevokedRange {
  range: string;
  reasonCode: string;
}

export interface UpdateManifest {
  schemaVersion: 1;
  releaseVersion: string;
  channel: "stable" | "beta" | "canary";
  publishedAt: string;
  minimumClientVersion?: string;
  revokedVersions: RevokedRange[];
  artifacts: UpdateArtifact[];
  skillBundle?: { version?: string; sha256?: string };
  keyId: string;
}

export interface SignedManifest {
  /** Canonical JSON of the manifest, base64. Signature covers exactly these bytes. */
  payload: string;
  signature: string;
  keyId: string;
  algorithm: "ed25519";
}

/** Deterministic serialization so signing and verification agree byte for byte. */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, item]) => item !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalize(item)}`).join(",")}}`;
}

export function generateSigningKeyPair(): { publicKeyPem: string; privateKeyPem: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  };
}

export function signManifest(manifest: UpdateManifest, privateKeyPem: string): SignedManifest {
  const canonical = Buffer.from(canonicalize(manifest), "utf8");
  const signature = crypto.sign(null, canonical, crypto.createPrivateKey(privateKeyPem));
  return {
    payload: canonical.toString("base64"),
    signature: signature.toString("base64"),
    keyId: manifest.keyId,
    algorithm: "ed25519"
  };
}

export type VerifyResult =
  | { valid: true; manifest: UpdateManifest }
  | { valid: false; reason: VerifyFailureReason; detail?: string };

export type VerifyFailureReason =
  | "unknown_key"
  | "bad_signature"
  | "malformed_payload"
  | "schema_invalid"
  | "stale_manifest"
  | "future_manifest"
  | "unsupported_algorithm";

export interface VerifyOptions {
  /** Pinned root keys, keyed by keyId. Embedded in the client. */
  trustedKeys: Record<string, string>;
  now?: Date;
  /** Replay window: a manifest older than this is refused. */
  maxAgeMs?: number;
  maxClockSkewMs?: number;
}

const DEFAULT_MAX_AGE_MS = 45 * 24 * 60 * 60 * 1000;
const DEFAULT_SKEW_MS = 10 * 60 * 1000;

/**
 * Update metadata is untrusted until this returns valid. A compromised API
 * response must not be able to select an artifact or run code.
 */
export function verifyManifest(signed: SignedManifest, options: VerifyOptions): VerifyResult {
  if (signed.algorithm !== "ed25519") return { valid: false, reason: "unsupported_algorithm" };
  const publicKeyPem = options.trustedKeys[signed.keyId];
  if (!publicKeyPem) return { valid: false, reason: "unknown_key", detail: signed.keyId };

  let canonical: Buffer;
  let signature: Buffer;
  try {
    canonical = Buffer.from(signed.payload, "base64");
    signature = Buffer.from(signed.signature, "base64");
  } catch {
    return { valid: false, reason: "malformed_payload" };
  }

  let signatureOk = false;
  try {
    signatureOk = crypto.verify(null, canonical, crypto.createPublicKey(publicKeyPem), signature);
  } catch {
    signatureOk = false;
  }
  if (!signatureOk) return { valid: false, reason: "bad_signature" };

  let parsed: unknown;
  try {
    parsed = JSON.parse(canonical.toString("utf8"));
  } catch {
    return { valid: false, reason: "malformed_payload" };
  }

  const schema = validateUpdateManifest(parsed);
  if (!schema.valid) return { valid: false, reason: "schema_invalid", detail: formatIssues(schema.issues) };

  const manifest = parsed as UpdateManifest;
  if (manifest.keyId !== signed.keyId) return { valid: false, reason: "bad_signature", detail: "key id mismatch" };

  const now = options.now ?? new Date();
  const published = new Date(manifest.publishedAt).getTime();
  const maxAge = options.maxAgeMs ?? DEFAULT_MAX_AGE_MS;
  const skew = options.maxClockSkewMs ?? DEFAULT_SKEW_MS;
  if (published > now.getTime() + skew) return { valid: false, reason: "future_manifest" };
  if (now.getTime() - published > maxAge) return { valid: false, reason: "stale_manifest" };

  return { valid: true, manifest };
}

export function verifyArtifact(body: Buffer, artifact: UpdateArtifact): { ok: boolean; reason?: string } {
  if (body.byteLength !== artifact.size) {
    return { ok: false, reason: `artifact size ${body.byteLength} does not match manifest size ${artifact.size}` };
  }
  const digest = crypto.createHash("sha256").update(body).digest("hex");
  if (digest !== artifact.sha256) return { ok: false, reason: "artifact digest does not match the signed manifest" };
  return { ok: true };
}
