import type { RevokedRange, UpdateArtifact, UpdateManifest } from "./manifest.js";

export interface Version {
  major: number;
  minor: number;
  patch: number;
  prerelease?: string;
}

export function parseVersion(value: string): Version | null {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/.exec(value.trim());
  if (!match) return null;
  const version: Version = { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]) };
  if (match[4]) version.prerelease = match[4];
  return version;
}

export function compareVersions(a: string, b: string): number {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (!left || !right) return 0;
  if (left.major !== right.major) return left.major - right.major;
  if (left.minor !== right.minor) return left.minor - right.minor;
  if (left.patch !== right.patch) return left.patch - right.patch;
  if (left.prerelease && !right.prerelease) return -1;
  if (!left.prerelease && right.prerelease) return 1;
  if (left.prerelease && right.prerelease) return left.prerelease < right.prerelease ? -1 : left.prerelease > right.prerelease ? 1 : 0;
  return 0;
}

/** Supported range forms: exact version, `<=x.y.z`, `<x.y.z`, `x.y.z - a.b.c`. */
export function versionInRange(version: string, range: string): boolean {
  const trimmed = range.trim();
  const dash = trimmed.split(" - ");
  if (dash.length === 2 && dash[0] && dash[1]) {
    return compareVersions(version, dash[0]) >= 0 && compareVersions(version, dash[1]) <= 0;
  }
  if (trimmed.startsWith("<=")) return compareVersions(version, trimmed.slice(2).trim()) <= 0;
  if (trimmed.startsWith("<")) return compareVersions(version, trimmed.slice(1).trim()) < 0;
  if (trimmed.startsWith(">=")) return compareVersions(version, trimmed.slice(2).trim()) >= 0;
  if (trimmed.startsWith(">")) return compareVersions(version, trimmed.slice(1).trim()) > 0;
  return compareVersions(version, trimmed) === 0;
}

export function findRevocation(version: string, revoked: RevokedRange[]): RevokedRange | null {
  return revoked.find((entry) => versionInRange(version, entry.range)) ?? null;
}

export type UpdateDecision =
  | { action: "up_to_date"; version: string }
  | { action: "update_available"; version: string; artifact: UpdateArtifact }
  | { action: "pinned"; version: string; availableVersion: string }
  | { action: "blocked_revoked"; version: string; reasonCode: string; upgradeTo: string }
  | { action: "blocked_below_minimum"; version: string; minimum: string; upgradeTo: string }
  | { action: "refused_downgrade"; version: string; offeredVersion: string }
  | { action: "no_artifact"; version: string; os: string; arch: string }
  | { action: "channel_mismatch"; version: string; channel: string };

export interface EvaluateInput {
  manifest: UpdateManifest;
  currentVersion: string;
  os: "darwin" | "windows" | "linux";
  arch: "x64" | "arm64";
  channel?: "stable" | "beta" | "canary";
  /** User or team pin. A pin never overrides revocation or a minimum version. */
  pinnedVersion?: string;
}

/**
 * Pure decision function. Revocation and minimum-version rules outrank pins and
 * downgrade refusal, because those exist to get a user off a dangerous build.
 */
export function evaluateUpdate(input: EvaluateInput): UpdateDecision {
  const { manifest, currentVersion } = input;
  const channel = input.channel ?? "stable";

  const revocation = findRevocation(currentVersion, manifest.revokedVersions ?? []);
  if (revocation) {
    return {
      action: "blocked_revoked",
      version: currentVersion,
      reasonCode: revocation.reasonCode,
      upgradeTo: manifest.releaseVersion
    };
  }

  if (manifest.minimumClientVersion && compareVersions(currentVersion, manifest.minimumClientVersion) < 0) {
    return {
      action: "blocked_below_minimum",
      version: currentVersion,
      minimum: manifest.minimumClientVersion,
      upgradeTo: manifest.releaseVersion
    };
  }

  if (manifest.channel !== channel) {
    return { action: "channel_mismatch", version: currentVersion, channel: manifest.channel };
  }

  if (input.pinnedVersion) {
    if (compareVersions(currentVersion, input.pinnedVersion) === 0) {
      return { action: "pinned", version: currentVersion, availableVersion: manifest.releaseVersion };
    }
  }

  const comparison = compareVersions(manifest.releaseVersion, currentVersion);
  if (comparison === 0) return { action: "up_to_date", version: currentVersion };
  if (comparison < 0) {
    return { action: "refused_downgrade", version: currentVersion, offeredVersion: manifest.releaseVersion };
  }

  const artifact = manifest.artifacts.find((entry) => entry.os === input.os && entry.arch === input.arch);
  if (!artifact) {
    return { action: "no_artifact", version: manifest.releaseVersion, os: input.os, arch: input.arch };
  }
  return { action: "update_available", version: manifest.releaseVersion, artifact };
}

export function describeDecision(decision: UpdateDecision, cliName: string): string {
  switch (decision.action) {
    case "up_to_date":
      return `${cliName} ${decision.version} is current.`;
    case "update_available":
      return `${cliName} ${decision.version} is available. Run "${cliName} update" to install it.`;
    case "pinned":
      return `${cliName} is pinned to ${decision.version}. ${decision.availableVersion} is available.`;
    case "blocked_revoked":
      return `This ${cliName} version was withdrawn (${decision.reasonCode}). Update to ${decision.upgradeTo} to continue syncing. Local reports still open.`;
    case "blocked_below_minimum":
      return `This ${cliName} version is below the minimum supported ${decision.minimum}. Update to ${decision.upgradeTo} to continue syncing.`;
    case "refused_downgrade":
      return `Refused a downgrade from ${decision.version} to ${decision.offeredVersion}.`;
    case "no_artifact":
      return `No signed ${cliName} artifact is published for ${decision.os}/${decision.arch} in this release.`;
    case "channel_mismatch":
      return `The manifest is for the ${decision.channel} channel and was ignored.`;
    default:
      return "Update state is unknown.";
  }
}

/** Sync is blocked on a dangerous build; local report access is not. */
export function blocksCloudSync(decision: UpdateDecision): boolean {
  return decision.action === "blocked_revoked" || decision.action === "blocked_below_minimum";
}
