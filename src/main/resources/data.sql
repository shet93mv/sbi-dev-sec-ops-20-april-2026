-- ═══════════════════════════════════════════════════════════════════════════
-- SBI EMS — Seed Data (Minimal — for DevSecOps Training)
-- ═══════════════════════════════════════════════════════════════════════════

-- ── 1. DEPARTMENTS (3 — just enough for demos) ───────────────────────────
INSERT INTO departments (id, name) VALUES
(1, 'Engineering'),
(2, 'HR'),
(3, 'DevOps');

-- ── 2. PROJECTS (3 — for the A04 state machine demo) ────────────────────
INSERT INTO projects (id, name, status) VALUES
(1, 'YONO 2.0',            'ACTIVE'),
(2, 'Core Banking Upgrade','PLANNED'),
(3, 'Analytics Hub',       'ON_HOLD');

-- ── 3. EMPLOYEES (5 — enough for all lab exercises) ─────────────────────
-- Employees include salary (PII) — A01 access control demo
-- Note: no passwords stored here — authentication uses in-memory users (see EmsUserDetailsService)
INSERT INTO employees (id, first_name, last_name, email, salary, status, department_id) VALUES
(1, 'Arjun',  'Sharma',   'arjun.sharma@sbi.co.in',   55000.00, 'ACTIVE', 1),
(2, 'Priya',  'Nair',     'priya.nair@sbi.co.in',     72000.00, 'ACTIVE', 1),
(3, 'Rajesh', 'Kumar',    'rajesh.kumar@sbi.co.in',   45000.00, 'ACTIVE', 2),
(4, 'Sunita', 'Patel',    'sunita.patel@sbi.co.in',   48000.00, 'ACTIVE', 3),
(5, 'Vikram', 'Singh',    'vikram.singh@sbi.co.in',   90000.00, 'ACTIVE', 3);
