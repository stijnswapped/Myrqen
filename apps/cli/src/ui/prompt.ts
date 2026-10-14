import readline from "node:readline/promises";

/**
 * Can this run ask the human a question and expect an answer?
 *
 * A terminal is not enough. Continuous-integration runners commonly allocate a
 * pty — GitLab CI, Jenkins, `docker run -t` — so `isTTY` is true while there is
 * nobody there to press a key, and a prompt in that shell hangs the job until it
 * times out. `TERM=dumb` says the same thing about a terminal that cannot render
 * the cursor control an interactive picker needs.
 *
 * These are the conventions the README tells users are honoured, so they are
 * honoured in the one place that decides whether to prompt.
 */
export function isInteractive(): boolean {
  if (process.env.MYRQEN_NON_INTERACTIVE === "1") return false;
  if (process.env.CI && process.env.CI !== "0" && process.env.CI !== "false") return false;
  if (process.env.TERM === "dumb") return false;
  return Boolean(process.stdin.isTTY && process.stdout.isTTY);
}

async function ask(question: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    return (await rl.question(question)).trim();
  } finally {
    rl.close();
  }
}

/**
 * Default-deny confirmation. In a non-interactive shell this never blocks and
 * never assumes yes: the caller must ask the human another way.
 */
export async function confirm(question: string, options: { defaultYes?: boolean } = {}): Promise<boolean> {
  if (!isInteractive()) return false;
  const suffix = options.defaultYes ? "[Y/n]" : "[y/N]";
  const answer = (await ask(`${question} ${suffix} `)).toLowerCase();
  if (answer === "") return Boolean(options.defaultYes);
  return answer === "y" || answer === "yes";
}

export async function choose(question: string, options: string[]): Promise<number | null> {
  if (!isInteractive() || options.length === 0) return null;
  process.stdout.write(`${question}\n`);
  options.forEach((option, index) => process.stdout.write(`  ${index + 1}. ${option}\n`));
  const answer = await ask("Choose a number: ");
  const index = Number(answer) - 1;
  if (!Number.isInteger(index) || index < 0 || index >= options.length) return null;
  return index;
}

export async function text(question: string): Promise<string | null> {
  if (!isInteractive()) return null;
  const answer = await ask(`${question} `);
  return answer.length > 0 ? answer : null;
}
