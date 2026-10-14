/**
 * The statistics every published figure in this project needs.
 *
 * Extracted so the corpus scorer and the agent harness cannot disagree about what an
 * interval means. Both report proportions over about thirty trials, and the whole reason
 * these functions exist is recorded in ruling U7: four blind runs were written up as a
 * declining trend when their 95% intervals all overlapped, and the differences that were
 * treated as findings were smaller than the measurement could resolve.
 */

/** Two-sided 95%. */
export const Z95 = 1.959963984540054;

/**
 * Wilson score interval for a binomial proportion.
 *
 * Wilson rather than the textbook normal approximation, because the normal one is wrong
 * exactly where these figures live — small n, proportions near 0 and 1 — and would put the
 * lower bound of a 0-of-32 false-positive rate below zero, which is not a number anybody
 * should publish.
 *
 * Returns null for a non-positive or non-finite denominator rather than NaN, so a caller
 * that has no trials yet prints "n/a" instead of a plausible-looking wrong figure.
 */
export function wilson(successes, trials, z = Z95) {
  if (!Number.isFinite(successes) || !Number.isFinite(trials) || trials <= 0) return null;
  const p = successes / trials;
  const denominator = 1 + (z * z) / trials;
  const centre = (p + (z * z) / (2 * trials)) / denominator;
  const half = (z * Math.sqrt((p * (1 - p)) / trials + (z * z) / (4 * trials * trials))) / denominator;
  return { point: p, low: Math.max(0, centre - half), high: Math.min(1, centre + half), n: trials };
}

/** `[low, high]` rounded to four places — anything finer is false precision on n = 30. */
export function intervalOf(value) {
  return value === null ? null : [Number(value.low.toFixed(4)), Number(value.high.toFixed(4))];
}

/** Abramowitz-Stegun 7.1.26. Accurate to ~1e-7, which is far past what these n support. */
function erf(x) {
  const t = 1 / (1 + 0.3275911 * x);
  return (
    1 -
    ((((1.061405429 * t - 1.453152027) * t + 1.421413741) * t - 0.284496736) * t + 0.254829592) *
      t *
      Math.exp(-x * x)
  );
}

/**
 * Two-proportion z-test, so "distinguishable" is computed rather than asserted.
 *
 * Returns null when either arm has no trials. `distinguishable` is the 95% verdict, and it is
 * deliberately the only interpretation this function offers: the p-value is returned beside it
 * so a reader can see how close the call was, not so a caller can hunt for a threshold that
 * makes their change look significant.
 */
export function twoProportion(k1, n1, k2, n2) {
  if (!(n1 > 0 && n2 > 0)) return null;
  const pooled = (k1 + k2) / (n1 + n2);
  if (pooled === 0 || pooled === 1) return { z: 0, p: 1, distinguishable: false };
  const se = Math.sqrt(pooled * (1 - pooled) * (1 / n1 + 1 / n2));
  if (se === 0) return { z: 0, p: 1, distinguishable: false };
  const z = (k1 / n1 - k2 / n2) / se;
  const p = 2 * (1 - 0.5 * (1 + erf(Math.abs(z) / Math.SQRT2)));
  return { z, p: Number(p.toFixed(4)), distinguishable: Math.abs(z) >= Z95 };
}

/**
 * McNemar's test for two conditions measured on the *same* cases.
 *
 * The right test for an arm comparison, and a materially different one from `twoProportion`.
 * Two independent proportions throw away the pairing and spend their power on between-case
 * variance — which case is hard — when the question is only about the cases where the two
 * arms disagreed. At n around 15 that difference decides whether anything is resolvable.
 *
 * `onlyA` is the count of cases the first arm got and the second missed, `onlyB` the reverse.
 * Cases both arms got, or both missed, carry no information about which is better and are
 * correctly ignored — that is the whole point of the test, not an omission.
 *
 * Uses the exact binomial rather than the chi-square approximation, because the discordant
 * counts here are small enough that the approximation is not trustworthy.
 */
export function mcnemar(onlyA, onlyB) {
  const n = onlyA + onlyB;
  if (n === 0) return { onlyA, onlyB, discordant: 0, p: 1, distinguishable: false };

  // Two-sided exact binomial against p = 0.5: the chance of a split this lopsided or worse.
  const choose = (total, k) => {
    let result = 1;
    for (let i = 0; i < k; i += 1) result = (result * (total - i)) / (i + 1);
    return result;
  };
  const extreme = Math.min(onlyA, onlyB);
  let tail = 0;
  for (let k = 0; k <= extreme; k += 1) tail += choose(n, k);
  const p = Math.min(1, 2 * tail * 0.5 ** n);
  return { onlyA, onlyB, discordant: n, p: Number(p.toFixed(4)), distinguishable: p < 0.05 };
}

/**
 * The smallest difference a sample of this size can separate, as a rule of thumb.
 *
 * Two 95% intervals at p = 0.5 stop overlapping at roughly `2 * z * sqrt(0.25/n)`. This is
 * the number to quote when somebody asks how big a change has to be before it means
 * anything — on the thirty-case corpora it is about 0.35, which is larger than any
 * improvement this project has ever produced in one step.
 */
export function resolution(trials) {
  if (!Number.isFinite(trials) || trials <= 0) return null;
  return 2 * Z95 * Math.sqrt(0.25 / trials);
}
