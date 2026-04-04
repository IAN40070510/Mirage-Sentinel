-- Convert monetary columns from floating-point to integer amounts (TWD style)
-- Safe to run on an existing Mirage-Sentinel PostgreSQL database.

BEGIN;

-- 1) Convert account balances to integer (rounded to nearest integer)
ALTER TABLE accounts
    ALTER COLUMN balance TYPE BIGINT USING ROUND(balance)::BIGINT,
    ALTER COLUMN balance SET DEFAULT 0;

-- 2) Convert transaction amounts/fees to integer (rounded)
ALTER TABLE transactions
    ALTER COLUMN amount TYPE BIGINT USING ROUND(amount)::BIGINT,
    ALTER COLUMN amount SET DEFAULT 0,
    ALTER COLUMN fee TYPE BIGINT USING ROUND(fee)::BIGINT,
    ALTER COLUMN fee SET DEFAULT 0;

-- 3) Normalize legacy USD demo records to TWD baseline if they still use old defaults
UPDATE accounts
SET currency = 'TWD',
    balance = 5680000
WHERE currency = 'USD' AND balance = 182700;

UPDATE transactions
SET currency = 'TWD'
WHERE currency = 'USD';

COMMIT;

-- Verification queries:
-- SELECT column_name, data_type FROM information_schema.columns WHERE table_name IN ('accounts','transactions') AND column_name IN ('balance','amount','fee');
-- SELECT currency, COUNT(*) FROM accounts GROUP BY currency;
-- SELECT currency, COUNT(*) FROM transactions GROUP BY currency;
