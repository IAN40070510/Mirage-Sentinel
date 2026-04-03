-- Mirage-Sentinel PostgreSQL seed data

CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS accounts (
    account_id VARCHAR(50) PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL REFERENCES users(user_id),
    account_type VARCHAR(50) DEFAULT 'Checking',
    currency VARCHAR(10) DEFAULT 'USD',
    balance DOUBLE PRECISION DEFAULT 0.0,
    status VARCHAR(20) DEFAULT 'ACTIVE',
    open_date VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transactions (
    tx_id VARCHAR(50) PRIMARY KEY,
    from_account VARCHAR(50) NOT NULL REFERENCES accounts(account_id),
    to_account VARCHAR(50) NOT NULL REFERENCES accounts(account_id),
    amount DOUBLE PRECISION NOT NULL,
    currency VARCHAR(10) DEFAULT 'USD',
    fee DOUBLE PRECISION DEFAULT 0.0,
    status VARCHAR(20) DEFAULT 'SUCCESS',
    note TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS beneficiaries (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL REFERENCES users(user_id),
    nickname VARCHAR(100) NOT NULL,
    bank_code VARCHAR(10) NOT NULL,
    account_id VARCHAR(50) NOT NULL,
    beneficiary_name VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, account_id)
);

CREATE TABLE IF NOT EXISTS idempotency (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL,
    idempotency_key VARCHAR(100) NOT NULL,
    tx_id VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, idempotency_key)
);

INSERT INTO users (user_id, name, email)
VALUES
    ('CIF000001001', 'Wang Xiaoming', 'wang@example.com'),
    ('CIF000001002', 'Lin Yating', 'lin@example.com')
ON CONFLICT (user_id) DO NOTHING;

INSERT INTO accounts (account_id, user_id, account_type, currency, balance, status, open_date)
VALUES
    ('ACCOD48PUCAEHKH', 'CIF000001001', 'Checking', 'USD', 182700.46, 'ACTIVE', '2021-03-27'),
    ('ACCZ1234567890AB', 'CIF000001002', 'Savings', 'USD', 1000000.00, 'ACTIVE', '2020-01-15')
ON CONFLICT (account_id) DO NOTHING;

INSERT INTO beneficiaries (user_id, nickname, bank_code, account_id, beneficiary_name)
VALUES
    ('CIF000001001', 'Primary Merchant', '812', 'ACCZ1234567890AB', 'Lin Yating')
ON CONFLICT (user_id, account_id) DO NOTHING;
