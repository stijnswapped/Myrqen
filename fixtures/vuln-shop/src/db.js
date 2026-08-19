/**
 * In-memory data store for the fixture. Deliberately simple so the defects in
 * the route handlers are the interesting part.
 */
export const users = [
  { id: 1, email: "alice@example.test", password: "alice-password-1", role: "customer", name: "Alice" },
  { id: 2, email: "bob@example.test", password: "bob-password-1", role: "customer", name: "Bob" },
  { id: 3, email: "root@example.test", password: "root-password-1", role: "admin", name: "Root" }
];

export const orders = [
  { id: 101, userId: 1, item: "Blue widget", total: 4200, address: "1 Alice Street", card: "4242" },
  { id: 102, userId: 2, item: "Red widget", total: 1900, address: "2 Bob Avenue", card: "4111" },
  { id: 103, userId: 3, item: "Admin widget", total: 100, address: "3 Root Road", card: "5555" }
];

export const products = [
  { id: 1, name: "Blue widget", price: 4200, description: "A blue widget" },
  { id: 2, name: "Red widget", price: 1900, description: "A red widget" },
  { id: 3, name: "Green widget", price: 2500, description: "A green widget" }
];

export const sessions = new Map();

/**
 * A toy query engine. `where` is interpolated into a predicate expression, which
 * is exactly the unsafe-composition pattern this fixture is meant to expose.
 */
export function query(table, where) {
  const rows = table === "products" ? products : table === "orders" ? orders : users;
  if (!where) return rows;
  // Unsafe: the caller's string is composed directly into executable logic.
  const predicate = new Function("row", `try { return (${where}); } catch (error) { return false; }`);
  return rows.filter((row) => predicate(row));
}
