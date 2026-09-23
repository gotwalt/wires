-- Seed for .scripts/demo-remote-cli.sh: the workbench's orders.db.
CREATE TABLE orders (
	id INTEGER PRIMARY KEY,
	customer TEXT NOT NULL,
	total REAL NOT NULL,
	placed_at TEXT NOT NULL
);
INSERT INTO orders (customer, total, placed_at) VALUES
	('acme', 120.00, '2026-09-01'),
	('acme', 75.50, '2026-09-03'),
	('globex', 310.25, '2026-09-04'),
	('initech', 42.00, '2026-09-07'),
	('globex', 18.99, '2026-09-10'),
	('umbrella', 999.00, '2026-09-12'),
	('acme', 64.10, '2026-09-15');
