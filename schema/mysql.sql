-- The same table for MySQL; private_key_enc is Vault Transit ciphertext.
CREATE TABLE IF NOT EXISTS dkim (
  id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  domain          VARCHAR(255)    NOT NULL,
  selector        VARCHAR(63)     NOT NULL,
  public_key      TEXT            NOT NULL,
  private_key_enc TEXT            NOT NULL,
  created_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_domain_selector (domain, selector),
  KEY idx_domain_lookup ((lower(trim(domain))), created_at, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
