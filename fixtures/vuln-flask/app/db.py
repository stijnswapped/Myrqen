"""In-memory SQLite store, seeded on import. Nothing persists between runs."""

import sqlite3
import threading

_lock = threading.Lock()
_connection = sqlite3.connect(":memory:", check_same_thread=False)
_connection.row_factory = sqlite3.Row

_connection.executescript(
    """
    CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT, role TEXT, name TEXT);
    CREATE TABLE notes (id INTEGER PRIMARY KEY, owner_id INTEGER, title TEXT, body TEXT);
    CREATE TABLE products (id INTEGER PRIMARY KEY, sku TEXT, name TEXT, price_cents INTEGER, hidden INTEGER DEFAULT 0);

    INSERT INTO users VALUES (1, 'alice@example.test', 'alice-password-1', 'customer', 'Alice');
    INSERT INTO users VALUES (2, 'bob@example.test', 'bob-password-1', 'customer', 'Bob');
    INSERT INTO users VALUES (3, 'root@example.test', 'root-password-1', 'admin', 'Root');

    INSERT INTO notes VALUES (201, 1, 'Groceries', 'Oat milk, coffee');
    INSERT INTO notes VALUES (202, 2, 'Door code', 'Back door is 4471');
    INSERT INTO notes VALUES (203, 2, 'Gift ideas', 'Field cap for Alice');

    INSERT INTO products VALUES (1, 'MUG-01', 'Enamel mug', 1500, 0);
    INSERT INTO products VALUES (2, 'TEE-02', 'Organic tee', 2500, 0);
    INSERT INTO products VALUES (3, 'CAP-03', 'Field cap', 1800, 0);
    INSERT INTO products VALUES (4, 'PROTO-9', 'Unreleased prototype', 99900, 1);
    """
)


def query(statement, params=()):
    """Run one statement under the store's lock and return plain dict rows."""
    with _lock:
        return [dict(row) for row in _connection.execute(statement, params).fetchall()]
