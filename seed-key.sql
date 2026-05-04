-- Kipple Labs registrar API key hash.
-- SHA-256 of the plaintext Bearer token. Plaintext never stored here;
-- it lives in Josh's password manager as "Axis Registry Admin" and on the
-- kipple-registrar worker as the REGISTRY_API_KEY secret.
--
-- Updated 2026-04-18: hash reflects the live key. An earlier hash
-- (74e03865260cb090007cd930b402ee6b101e1887cddfe789b0d368c868c6a947)
-- was from a rotated/superseded key and has been replaced.

UPDATE registrars SET api_key_hash = '65672c128a950ae0fdda36d221aee92ad30815924e9ee58747afef678ad33275' WHERE id = 'kipple-labs';
