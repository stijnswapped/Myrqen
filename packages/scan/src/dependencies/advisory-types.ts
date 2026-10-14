/** One affected range from an OSV record: `introduced <= v < fixed`, or `<= lastAffected`. */
export interface AdvisoryRange {
  introduced: string;
  fixed?: string;
  lastAffected?: string;
}

export interface Advisory {
  /** GHSA identifier. */
  id: string;
  /** CVE aliases, when the advisory has any. */
  aliases: string[];
  package: string;
  summary: string;
  severity: "critical" | "high" | "medium" | "low";
  cwe: string[];
  ranges: AdvisoryRange[];
  /** Curated: module exports whose code is affected. `default` is the module itself. */
  exports?: string[];
  /** Curated: subpath modules that are the same code, such as `lodash/merge`. */
  subpaths?: string[];
  /** Curated: methods on an object the package returns. A weaker signal than an export. */
  members?: string[];
}

export interface AdvisorySnapshot {
  source: string;
  newestRecord: string | null;
  packages: string[];
  advisories: Advisory[];
}
