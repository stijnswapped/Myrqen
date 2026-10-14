"""In-memory SQLite store, seeded on import. Nothing persists between runs."""

import sqlite3

_connection = sqlite3.connect(":memory:", check_same_thread=False)
_connection.row_factory = sqlite3.Row

_connection.executescript(
    """
    CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT, role TEXT, name TEXT);
    CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, reference TEXT, total_cents INTEGER, address TEXT);
    CREATE TABLE products (id INTEGER PRIMARY KEY, sku TEXT, name TEXT, price_cents INTEGER, hidden INTEGER DEFAULT 0);

    INSERT INTO users VALUES (1, 'alice@example.test', 'alice-password-1', 'customer', 'Alice');
    INSERT INTO users VALUES (2, 'bob@example.test', 'bob-password-1', 'customer', 'Bob');
    INSERT INTO users VALUES (3, 'root@example.test', 'root-password-1', 'admin', 'Root');

    INSERT INTO orders VALUES (101, 1, 'A-101', 4200, '1 Alice Street');
    INSERT INTO orders VALUES (102, 2, 'B-102', 1999, '2 Bob Road');
    INSERT INTO orders VALUES (103, 2, 'B-103', 750, '2 Bob Road');

    INSERT INTO products VALUES (1, 'MUG-01', 'Enamel mug', 1500, 0);
    INSERT INTO products VALUES (2, 'TEE-02', 'Organic tee', 2500, 0);
    INSERT INTO products VALUES (3, 'CAP-03', 'Field cap', 1800, 0);
    INSERT INTO products VALUES (4, 'PROTO-9', 'Unreleased prototype', 99900, 1);
    """
)


def get_db():
    """Yield the shared connection.

    No lock is held across the request: the import route fetches a URL on this
    same server, and a request-long lock would deadlock it. The workload is a
    handful of reads from one tester, which SQLite serialises on its own.
    """
    yield _connection
