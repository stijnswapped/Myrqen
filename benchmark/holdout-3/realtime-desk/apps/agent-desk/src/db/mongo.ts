import { MongoClient } from "mongodb";

const client = new MongoClient(process.env.MONGO_URL ?? "mongodb://127.0.0.1:27017", {
  maxPoolSize: 20,
  serverSelectionTimeoutMS: 5_000
});

await client.connect();

const db = client.db(process.env.MONGO_DB ?? "deskline");

/**
 * The queue projections live in Mongo because the console re-sorts them on
 * every keystroke and the shapes change per tenant. Tickets of record are
 * still Postgres; these documents are derived and disposable.
 */
export const collections = {
  tickets: db.collection("ticket_projections"),
  queues: db.collection("queues"),
  presence: db.collection("presence")
};
