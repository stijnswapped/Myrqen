type Fields = Record<string, unknown>;

function emit(level: string, message: string, fields: Fields) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, message, ...fields }));
}

export const logger = {
  info: (message: string, fields: Fields = {}) => emit("info", message, fields),
  warn: (message: string, fields: Fields = {}) => emit("warn", message, fields),
  error: (message: string, fields: Fields = {}) => emit("error", message, fields),
};
