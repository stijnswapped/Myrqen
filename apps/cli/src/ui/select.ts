import readline from "node:readline";
import { style } from "./output.js";
import { isInteractive } from "./prompt.js";

/**
 * Selection lists, with no dependency and no assumptions about the terminal.
 *
 * A real multi-select needs raw mode. Raw mode is not available in every place a
 * developer runs a CLI — a CI shell, a pipe, an IDE task runner, a terminal in a
 * container — and a setup tool that becomes unusable there is a setup tool people
 * stop trusting. So each control here has two implementations: the arrow-key one
 * when the terminal can do it, and a typed one when it cannot. Neither ever
 * guesses an answer on the user's behalf.
 */

const ESC = "";
const CURSOR_HIDE = `${ESC}[?25l`;
const CURSOR_SHOW = `${ESC}[?25h`;
const CLEAR_LINE = `${ESC}[K`;
const up = (lines: number): string => `${ESC}[${lines}A`;

export interface Choice {
  value: string;
  label: string;
  /** Right-hand annotation, such as a detection state. */
  hint?: string;
  /** Pre-ticked in a multi-select. */
  selected?: boolean;
  /** Shown but not selectable, with the reason. */
  disabled?: string;
}

function canUseRawMode(): boolean {
  return isInteractive() && Boolean(process.stdin.isTTY && typeof process.stdin.setRawMode === "function");
}

function render(title: string, choices: Choice[], index: number, multi: boolean, first: boolean): void {
  if (!first) process.stdout.write(up(choices.length + 1));
  process.stdout.write(`${title}${CLEAR_LINE}\n`);
  choices.forEach((choice, position) => {
    const cursor = position === index ? style.brand("›") : " ";
    const mark = choice.disabled
      ? style.dim("·")
      : multi
        ? choice.selected
          ? style.brand("◉")
          : style.dim("○")
        : position === index
          ? style.brand("◉")
          : style.dim("○");
    const label = choice.disabled ? style.dim(choice.label) : choice.label;
    const hint = choice.disabled
      ? style.dim(`  ${choice.disabled}`)
      : choice.hint
        ? style.dim(`  ${choice.hint}`)
        : "";
    process.stdout.write(`${cursor} ${mark} ${label}${hint}${CLEAR_LINE}\n`);
  });
}

async function interactiveList(title: string, choices: Choice[], multi: boolean): Promise<string[] | null> {
  if (choices.every((choice) => choice.disabled)) return [];

  return new Promise((resolve) => {
    let index = choices.findIndex((choice) => !choice.disabled);
    const state = choices.map((choice) => Boolean(choice.selected));

    readline.emitKeypressEvents(process.stdin);
    process.stdin.setRawMode(true);
    process.stdout.write(CURSOR_HIDE);
    render(title, choices, index, multi, true);

    const cleanup = (): void => {
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stdin.off("keypress", onKey);
      process.stdout.write(CURSOR_SHOW);
    };

    const move = (delta: number): void => {
      for (let step = 0; step < choices.length; step += 1) {
        index = (index + delta + choices.length) % choices.length;
        if (!choices[index]!.disabled) break;
      }
    };

    function onKey(_: string, key: { name?: string; ctrl?: boolean; sequence?: string }): void {
      if (key.ctrl && key.name === "c") {
        cleanup();
        process.stdout.write("\n");
        resolve(null);
        return;
      }
      if (key.name === "up" || key.name === "k") move(-1);
      else if (key.name === "down" || key.name === "j") move(1);
      else if (multi && (key.name === "space" || key.sequence === " ")) state[index] = !state[index];
      else if (multi && key.name === "a") {
        const turningOn = state.some((value, position) => !value && !choices[position]!.disabled);
        choices.forEach((choice, position) => {
          if (!choice.disabled) state[position] = turningOn;
        });
      } else if (key.name === "return") {
        cleanup();
        resolve(
          multi
            ? choices.filter((choice, position) => state[position] && !choice.disabled).map((choice) => choice.value)
            : [choices[index]!.value]
        );
        return;
      } else if (key.name === "escape") {
        cleanup();
        resolve(null);
        return;
      }
      choices.forEach((choice, position) => {
        choice.selected = state[position] === true;
      });
      render(title, choices, index, multi, false);
    }

    process.stdin.on("keypress", onKey);
    process.stdin.resume();
  });
}

async function typedList(title: string, choices: Choice[], multi: boolean): Promise<string[] | null> {
  const rl = readline.promises.createInterface({ input: process.stdin, output: process.stdout });
  try {
    process.stdout.write(`${title}\n`);
    choices.forEach((choice, position) => {
      const marker = choice.disabled ? "unavailable" : choice.selected ? "selected" : "";
      process.stdout.write(
        `  ${position + 1}. ${choice.label}${choice.hint ? style.dim(`  ${choice.hint}`) : ""}${
          marker ? ` ${style.dim(`(${marker})`)}` : ""
        }\n`
      );
    });
    const prompt = multi
      ? "Numbers separated by commas, 'all', or Enter to accept the pre-selected set: "
      : "Choose a number: ";
    const answer = (await rl.question(prompt)).trim();

    if (multi && answer === "") {
      return choices.filter((choice) => choice.selected && !choice.disabled).map((choice) => choice.value);
    }
    if (multi && /^all$/i.test(answer)) {
      return choices.filter((choice) => !choice.disabled).map((choice) => choice.value);
    }
    if (multi && /^none$/i.test(answer)) return [];

    const picked = answer
      .split(",")
      .map((part) => Number(part.trim()) - 1)
      .filter((position) => Number.isInteger(position) && position >= 0 && position < choices.length)
      .map((position) => choices[position]!)
      .filter((choice) => !choice.disabled);

    if (picked.length === 0) return null;
    return multi ? picked.map((choice) => choice.value) : [picked[0]!.value];
  } finally {
    rl.close();
  }
}

/** Returns null when the user cancelled or no terminal answer was possible. */
export async function selectOne(title: string, choices: Choice[]): Promise<string | null> {
  if (!isInteractive()) return null;
  const chosen = canUseRawMode() ? await interactiveList(title, choices, false) : await typedList(title, choices, false);
  return chosen && chosen.length > 0 ? chosen[0]! : null;
}

export async function selectMany(title: string, choices: Choice[]): Promise<string[] | null> {
  if (!isInteractive()) return null;
  return canUseRawMode() ? interactiveList(title, choices, true) : typedList(title, choices, true);
}

/** The hint shown under a multi-select, so the controls are discoverable. */
export function multiSelectHelp(): string {
  return canUseRawMode()
    ? "up/down moves, space toggles, a toggles all, enter confirms"
    : "type the numbers you want, separated by commas";
}
