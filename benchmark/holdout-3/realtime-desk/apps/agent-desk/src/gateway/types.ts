import type { Socket } from "socket.io";

export interface DeskSession {
  agentId: string;
  orgId: string;
  role: "agent" | "lead" | "admin";
}

export interface DeskSocketData {
  session: DeskSession;
}

/**
 * The event map is open on purpose: handlers are registered by feature modules
 * that ship independently, so a closed union would mean editing this file for
 * every new event. The payloads are narrowed inside each handler instead.
 */
export interface DeskEvents {
  [event: string]: (...args: any[]) => void;
}

export type DeskSocket = Socket<DeskEvents, DeskEvents, DeskEvents, DeskSocketData>;

export type AckResponse<T> = ({ ok: true } & T) | { ok: false; error: string };
export type Ack<T> = (response: AckResponse<T>) => void;
