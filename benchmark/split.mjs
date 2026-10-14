import { createHash } from "node:crypto";

/**
 * Which half of a growable corpus a family belongs to.
 *
 * ## Why this file exists
 *
 * Seven held-out runs were each scored once and then burned, and the reasoning was sound:
 * a corpus the engine has been fixed against cannot measure whether the fix generalises.
 * Implemented as "score once, discard", it also caps the sample at whatever one authoring
 * round produces — about thirty vulnerable cases — forever.
 *
 * That cap is the thing that actually went wrong. Thirty cases give a 95% interval about
 * 0.31 wide, so the three comparable blind figures (0.300, 0.333, 0.250) are
 * indistinguishable from each other, and every conclusion drawn from their differences was
 * drawn from noise. Ruling U7 records that in full.
 *
 * A permanent holdout keeps the anti-tuning guarantee and drops the cap. What made the old
 * protocol trustworthy was never the discarding — it was that nobody had seen the corpus.
 * That property can be held indefinitely for *half* a corpus while the other half is used
 * freely, and then the holdout can be scored on every commit instead of once in its life.
 *
 * ## Why the split is by family and not by case
 *
 * A case-level split leaves both halves sharing authors, stacks, idioms and vocabulary.
 * Fixing a shape seen in the development half would then fix the same shape in the holdout,
 * and the holdout would report an improvement it had no independent evidence for — which is
 * the failure mode of a held-out set that is held out in name only.
 *
 * Splitting whole families means the holdout contains frameworks and data layers the
 * development half never shows. That is precisely the property the single-use protocol was
 * buying, and it survives being scored repeatedly.
 *
 * ## Why a hash and not a list
 *
 * Nobody chooses the assignment, so nobody can be accused of having chosen it — including
 * later, by themselves. The input is the family's own directory name, the function is
 * fixed, and anyone can recompute the whole split from this file. It is also stable as the
 * corpus grows: adding a family cannot move an existing one, so the holdout only ever gains
 * cases and every figure computed from it stays comparable with the last.
 *
 * A consequence worth stating: the split will not be exactly even, and forcing it to be
 * even would mean choosing. An imbalance of a few families is the price of the assignment
 * being unarguable.
 */
export const SPLITS = ["dev", "holdout"];

/**
 * The family's half, from the family name alone.
 *
 * SHA-256 of the name, first byte, low bit. Any stable hash would do; the point is that it
 * is written down and reproducible rather than that it is cryptographic.
 */
export function splitOf(family) {
  const digest = createHash("sha256").update(`myrqen-reference-split:${family}`).digest();
  return (digest[0] & 1) === 0 ? "dev" : "holdout";
}

/** Group family names by their half, for reporting how the split actually landed. */
export function partition(families) {
  const out = { dev: [], holdout: [] };
  for (const family of [...families].sort()) out[splitOf(family)].push(family);
  return out;
}

/**
 * Does this split allow per-case detail to be printed?
 *
 * No, for the holdout, and this is the only mechanism in the repository that enforces the
 * discipline rather than asking for it. A permanent holdout is only worth anything while
 * nobody has looked at its cases, and "do not look" is not a control — the first time a
 * figure drops, the natural next step is to ask *which case*, and answering that question
 * is what converts a holdout into a development corpus.
 *
 * So the holdout answers aggregates and refuses to name a case. Diagnosing one becomes a
 * deliberate act requiring a code change, which is a bar low enough to clear when there is
 * a real reason and high enough that it cannot happen by momentum.
 */
export function allowsCaseDetail(split) {
  return split !== "holdout";
}
