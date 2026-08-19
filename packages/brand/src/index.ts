/**
 * Single source of truth for brand-sensitive identifiers.
 *
 * Myrqen is a working codename. A rename must be a mechanical change here plus
 * a migration of persisted values that embed these strings (config directory,
 * credential prefixes). Do not scatter literals through product logic.
 */
export interface BrandIdentity {
  readonly displayName: string;
  readonly uppercaseName: string;
  readonly cliName: string;
  readonly configDirectoryName: string;
  readonly repoStateDirectoryName: string;
  readonly skillId: string;
  readonly deviceTokenPrefix: string;
  readonly linkCodePrefix: string;
  readonly userAgentProduct: string;
  readonly analyticsProductName: string;
  readonly reportFooter: string;
  readonly packageName: string;
  readonly reportSchemaVersion: string;
  readonly pronunciation: string;
  readonly tagline: string;
  /** Apex domain the product ships under. */
  readonly domain: string;
  /** Documentation site, hosted separately from the application. */
  readonly docsUrl: string;
  /**
   * The source-available repository shown on the marketing site. It is NOT open
   * source: copyright is retained and the licence grants reading, not reuse.
   * Never describe it as open source in product copy.
   */
  readonly sourceRepoUrl: string;
  /** The deployed application's own repository, which is not published. */
  readonly applicationRepoUrl: string;
}

export const BRAND: BrandIdentity = Object.freeze({
  displayName: "Myrqen",
  uppercaseName: "MYRQEN",
  cliName: "myrqen",
  configDirectoryName: "myrqen",
  repoStateDirectoryName: ".myrqen",
  skillId: "myrqen",
  deviceTokenPrefix: "myrq_dev_",
  linkCodePrefix: "myrq_link_",
  userAgentProduct: "myrqen-cli",
  analyticsProductName: "myrqen",
  reportFooter: "Myrqen security assessment output. Working brand pending final clearance.",
  packageName: "myrqen",
  reportSchemaVersion: "1.0.0",
  pronunciation: "MIR-ken",
  tagline: "Security testing, inside your coding agent.",
  domain: "myrqen.cc",
  docsUrl: "https://docs.myrqen.cc",
  sourceRepoUrl: "https://github.com/stijnswapped/Myrqen",
  applicationRepoUrl: "https://github.com/stijnswapped/Myrqen.cc"
});

/**
 * Tests may substitute an alternate identity to expose hard-coded brand
 * assumptions. Product code must accept an injected identity rather than
 * importing BRAND deep inside logic where practical.
 */
export function makeBrand(overrides: Partial<BrandIdentity>): BrandIdentity {
  return Object.freeze({ ...BRAND, ...overrides });
}

export const CLI_VERSION = "0.1.0";
export const SKILL_BUNDLE_VERSION = "0.1.0";
