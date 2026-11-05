-- One key per domain; private_key_enc is Vault Transit ciphertext (vault:v1:...).
CREATE TABLE IF NOT EXISTS dkim (
  id              BIGSERIAL PRIMARY KEY,
  domain          TEXT NOT NULL,
  selector        TEXT NOT NULL,
  public_key      TEXT NOT NULL,
  private_key_enc TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (domain, selector)
);
CREATE INDEX IF NOT EXISTS dkim_domain ON dkim (domain);
