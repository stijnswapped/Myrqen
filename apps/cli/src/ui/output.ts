import { BRAND } from "@myrqen/brand";

const ESC = "\u001b";
const isTty = Boolean(process.stdout.isTTY);
const noColor = Boolean(process.env.NO_COLOR) || process.env.MYRQEN_NO_COLOR === "1";

function paint(code: string, value: string): string {
  if (!isTty || noColor) return value;
  return `${ESC}[${code}m${value}${ESC}[0m`;
}

export const style = {
  brand: (value: string) => paint("38;5;155", value),
  dim: (value: string) => paint("2", value),
  bold: (value: string) => paint("1", value),
  ok: (value: string) => paint("38;5;114", value),
  warn: (value: string) => paint("38;5;179", value),
  bad: (value: string) => paint("38;5;203", value)
};

export function write(line = ""): void {
  process.stdout.write(`${line}\n`);
}

export function heading(subtitle?: string): void {
  write(`${style.brand(BRAND.displayName)}${subtitle ? ` ${style.dim(subtitle)}` : ""}`);
}

export function field(label: string, value: string): void {
  write(`${style.dim(`${label}:`)} ${value}`);
}

export function bullet(value: string): void {
  write(`  ${style.dim("-")} ${value}`);
}

export function blank(): void {
  write();
}

/**
 * Capability gaps are stated once, calmly, and never repeated as warnings.
 * See docs/07-ux/ONBOARDING.md.
 */
export function capabilityNote(value: string): void {
  write(style.dim(value));
}

export function warn(value: string): void {
  process.stderr.write(`${style.warn(value)}\n`);
}

export function fail(value: string): void {
  process.stderr.write(`${style.bad(value)}\n`);
}

export function json(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}
