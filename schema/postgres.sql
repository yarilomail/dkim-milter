-- One row per domain and selector; the newest row of a domain signs; private_key_enc is Vault Transit ciphertext (vault:v1:...).
CREATE TABLE IF NOT EXISTS dkim (
  id              BIGSERIAL PRIMARY KEY,
  domain          TEXT NOT NULL,
  selector        TEXT NOT NULL,
  public_key      TEXT NOT NULL,
  private_key_enc TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (domain, selector)
);
-- The key query: a domain's newest row, the domain without case and spaces.
CREATE INDEX IF NOT EXISTS dkim_domain_lookup ON dkim (lower(trim(domain)), created_at DESC, id DESC);
