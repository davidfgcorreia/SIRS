-- Populate tables  TODO: change ip, port, public_key
INSERT INTO destination_ips (company, ip, port, public_key)
VALUES 
    ('Lays Chips',              '127.0.0.1', 8443, 'keys/lays-chips-public.key'), -- Devia ser a chave em si e nao a localizacao do ficheiro 
    ('Stealing Corporation',    '127.0.0.1', 8444, 'keys/stealing-corporation-public.key'),
    ('Ching Chong Extractions', '127.0.0.1', 8445, 'keys/ching-chong-extractions-public.key')
ON CONFLICT (company) DO NOTHING;

INSERT INTO transaction (id, timestamp, seller, buyer, product, units, amount)
VALUES
    (1, 1764069200, 'Ching Chong Extractions', 'Lays Chips'), -- FIXME: how to do add a binary?
    (2, 1764069300, 'Lays Chips', 'Ching Chong Extractions');

INSERT INTO transaction_shares (id, share, shared_by)
VALUES
    (1, 'Ching Chong Extractions', 'buyer'),
    (1, 'Lays Chips', 'buyer'),
    (2, 'Ching Chong Extractions', 'buyer'),
    (2, 'Lays Chips', 'buyer'),
    (1, 'Stealing Corporation', 'Seller'),
    (2, 'Stealing Corporation', 'Seller');
