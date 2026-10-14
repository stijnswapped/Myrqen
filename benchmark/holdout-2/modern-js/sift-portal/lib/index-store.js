import { readFile } from "node:fs/promises";

let documents = null;

async function load() {
  if (!documents) {
    documents = JSON.parse(await readFile(new URL("../data/index.json", import.meta.url), "utf8"));
  }
  return documents;
}

function snippetFor(text, term) {
  const at = text.toLowerCase().indexOf(term.toLowerCase());
  const from = Math.max(0, at - 40);
  return `${from > 0 ? "…" : ""}${text.slice(from, from + 160)}…`;
}

export async function searchDocuments(term, { page = 1, pageSize = 20 } = {}) {
  const all = await load();
  const needle = term.toLowerCase();
  const matches = all.filter((document) => document.body.toLowerCase().includes(needle));
  return matches.slice((page - 1) * pageSize, page * pageSize).map((document) => ({
    url: document.url,
    title: document.title,
    collection: document.collection,
    snippet: snippetFor(document.body, term),
  }));
}

export async function listPeople({ team = null, page = 1, pageSize = 20 } = {}) {
  const all = JSON.parse(await readFile(new URL("../data/people.json", import.meta.url), "utf8"));
  const matches = team ? all.filter((person) => person.team === team) : all;
  return matches.slice((page - 1) * pageSize, page * pageSize);
}
