-- create table transaction
CREATE TABLE IF NOT EXISTS transaction (
    id BIGINT PRIMARY KEY, -- FIXME: why shouldn't ids be SERIAL?
    timestamp BIGINT NOT NULL,
    seller VARCHAR(255) NOT NULL,
    buyer VARCHAR(255) NOT NULL,
    product VARCHAR(255) NOT NULL,
    units BIGINT NOT NULL,
    amount BIGINT NOT NULL
);

-- create table transaction_shares
CREATE TABLE IF NOT EXISTS transaction_shares (
    id BIGINT NOT NULL,
    share VARCHAR(255) NOT NULL,
    shared_by VARCHAR(16) NOT NULL, -- either seller or buyer
    PRIMARY KEY (id, share),
    FOREIGN KEY(id) REFERENCES transaction(id) ON DELETE CASCADE
);

-- create table destination_ips
CREATE TABLE IF NOT EXISTS destination_ips (
    company VARCHAR(255) PRIMARY KEY,
    ip VARCHAR(32) NOT NULL,
    port INTEGER NOT NULL,
    public_key TEXT NOT NULL
);

-- Populate tables  TODO: change ip, port, public_key
INSERT INTO destination_ips (company, ip, port, public_key)
VALUES 
    ('Lays Chips',              '127.0.0.1', 8443, 'keys/lays-chips-public.key'), -- Devia ser a chave em si e nao a localizacao do ficheiro 
    ('Stealing Corporation',    '127.0.0.1', 8444, 'keys/stealing-corporation-public.key'),
    ('Ching Chong Extractions', '127.0.0.1', 8445, 'keys/ching-chong-extractions-public.key')
ON CONFLICT (company) DO NOTHING;

INSERT INTO transaction (id, timestamp, seller, buyer, product, units, amount)
VALUES
    (1, 1764069200, 'Ching Chong Extractions', 'Lays Chips', 'Uranium', 67000, 676767),
    (2, 1764069300, 'Lays Chips', 'Ching Chong Extractions', 'Plutonium', 21000, 212121);

INSERT INTO transaction_shares (id, share, shared_by)
VALUES
    (1, 'Ching Chong Extractions', 'buyer'),
    (1, 'Lays Chips', 'buyer'),
    (2, 'Ching Chong Extractions', 'buyer'),
    (2, 'Lays Chips', 'buyer'),
    (1, 'Stealing Corporation', 'Seller'),
    (2, 'Stealing Corporation', 'Seller');
