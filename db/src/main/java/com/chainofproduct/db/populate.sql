-- create table transaction
CREATE TABLE IF NOT EXISTS transaction (
    id BIGINT PRIMARY KEY, -- FIXME: why shouldn't ids be SERIAL?
    timestamp BIGINT NOT NULL,
    seller VARCHAR(255) NOT NULL,
    buyer VARCHAR(255) NOT NULL,
    product VARCHAR(255) NOT NULL,
    units BIGINT NOT NULL,
    amount BIGINT NOT NULL,
    seller_signature TEXT NOT NULL, -- SR3: Digital signature from seller
    buyer_signature TEXT NOT NULL, -- SR3: Digital signature from buyer
    encrypted_data TEXT -- SR1: Encrypted transaction for confidentiality
);

-- create table transaction_shares
CREATE TABLE IF NOT EXISTS transaction_shares (
    id BIGINT NOT NULL,
    share VARCHAR(255) NOT NULL,
    shared_by VARCHAR(255) NOT NULL, -- company name that shared
    share_timestamp BIGINT NOT NULL, -- SR4: When was it shared
    share_signature TEXT NOT NULL, -- SR4: Cryptographic proof of who shared
    PRIMARY KEY (id, share, shared_by),
    FOREIGN KEY(id) REFERENCES transaction(id) ON DELETE CASCADE
);

-- create table companies
-- In centralized architecture, this table stores registered companies and their public keys
CREATE TABLE IF NOT EXISTS companies (
    name VARCHAR(255) PRIMARY KEY,
    public_key TEXT NOT NULL
);

-- Populate company information (public keys for encryption)
INSERT INTO companies (name, public_key)
VALUES 
    ('Lays Chips', 'keys/lays-chips-public.key'),
    ('Stealing Corporation', 'keys/stealing-corporation-public.key'),
    ('Ching Chong Extractions', 'keys/ching-chong-extractions-public.key')
ON CONFLICT (name) DO NOTHING;

-- Test data removed - will be inserted with proper signatures by application code
