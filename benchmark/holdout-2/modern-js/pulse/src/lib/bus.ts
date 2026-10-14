import { EventEmitter } from "node:events";

export interface BusEvent {
  id: string;
  type: string;
  payload: unknown;
}

const emitter = new EventEmitter();
emitter.setMaxListeners(0);

export function publish(topic: string, event: BusEvent): void {
  emitter.emit(topic, event);
}

/** Subscribes to a topic and returns the unsubscribe function. */
export function subscribe(topic: string, listener: (event: BusEvent) => void): () => void {
  emitter.on(topic, listener);
  return () => emitter.off(topic, listener);
}
