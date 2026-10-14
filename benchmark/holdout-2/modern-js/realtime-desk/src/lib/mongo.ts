import { MongoClient } from "mongodb";

const client = new MongoClient(process.env.MONGO_URL ?? "mongodb://127.0.0.1:27017");
await client.connect();

export const desk = client.db("desk");
export const conversations = desk.collection("conversations");
export const contacts = desk.collection("contacts");
