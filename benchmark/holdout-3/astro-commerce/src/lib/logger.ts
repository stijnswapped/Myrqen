type Level = "debug" | "info" | "warn" | "error";

const THRESHOLD: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };
const MIN = THRESHOLD[(import.meta.env.LOG_LEVEL as Level | undefined) ?? "info"];

function emit(level: Level, message: string, fields: Record<string, unknown>) {
  if (THRESHOLD[level] < MIN) return;
  process.stdout.write(`${JSON.stringify({ ts: new Date().toISOString(), level, message, ...fields })}\n`);
}

export const logger = {
  debug: (message: string, fields: Record<string, unknown> = {}) => emit("debug", message, fields),
  info: (message: string, fields: Record<string, unknown> = {}) => emit("info", message, fields),
  warn: (message: string, fields: Record<string, unknown> = {}) => emit("warn", message, fields),
  error: (message: string, fields: Record<string, unknown> = {}) => emit("error", message, fields)
};
