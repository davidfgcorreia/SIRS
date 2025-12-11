DROP TABLE IF EXISTS transaction;
DROP TABLE IF EXISTS transaction_shares;
DROP TABLE IF EXISTS destination_ips;
DROP TABLE IF EXISTS groups;
-- create table transaction
CREATE TABLE IF NOT EXISTS transaction (
    id BIGINT PRIMARY KEY, -- FIXME: why shouldn't ids be SERIAL?
    seller VARCHAR(255) NOT NULL,
    buyer VARCHAR(255) NOT NULL,
    raw_file BYTEA NOT NULL
);

-- create table transaction_shares
CREATE TABLE IF NOT EXISTS transaction_shares (
    id BIGINT NOT NULL,
    share VARCHAR(255) NOT NULL,
    shared_by VARCHAR(16) NOT NULL, -- either seller or buyer
    shared_name VARCHAR(255) NOT NULL,
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

CREATE TABLE IF NOT EXISTS groups (
    name VARCHAR(255) PRIMARY KEY,
    leader VARCHAR(255) NOT NULL,
    FOREIGN KEY(leader) REFERENCES destination_ips(company) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS group_members (
    name VARCHAR(255) NOT NULL,
    company VARCHAR(255) NOT NULL,
    PRIMARY KEY (name, company),
    FOREIGN KEY(name) REFERENCES groups(name) ON DELETE CASCADE,
    FOREIGN KEY(company) REFERENCES destination_ips(company) ON DELETE CASCADE
);

