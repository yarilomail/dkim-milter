package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultListenAddr   = "0.0.0.0:8891"
	defaultMetricsAddr  = "0.0.0.0:8081"
	defaultCacheSize    = 10000
	defaultCacheTTL     = 600
	defaultCacheMissTTL = 60
	defaultSATokenFile  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

type config struct {
	listenAddr  string
	metricsAddr string

	dbDriver string // postgres | mysql
	dbDSN    string
	query    string

	decrypt string // vault | none
	vault   vaultConfig

	cacheSize    int
	cacheTTL     time.Duration
	cacheMissTTL time.Duration
}

// defaultQueries read one domain's row; the placeholder is the driver's.
var defaultQueries = map[string]string{
	"postgres": "SELECT domain, selector, private_key_enc FROM dkim WHERE domain = $1",
	"mysql":    "SELECT domain, selector, private_key_enc FROM dkim WHERE domain = ?",
}

// positive reads a whole number above zero.
func positive(name string, def int) (int, error) {
	v, err := strconv.Atoi(env(name, strconv.Itoa(def)))
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("config: %s %q: a whole number above 0", name, os.Getenv(name))
	}
	return v, nil
}

type vaultConfig struct {
	addr        string
	authPath    string
	role        string
	tokenFile   string
	caCert      string
	transitPath string
	transitKey  string
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func loadConfig() (config, error) {
	c := config{
		listenAddr:  env("LISTEN_ADDR", defaultListenAddr),
		metricsAddr: env("METRICS_ADDR", defaultMetricsAddr),
		dbDriver:    strings.ToLower(env("DB_DRIVER", "postgres")),
		dbDSN:       os.Getenv("DB_DSN"),
		decrypt:     strings.ToLower(env("KEY_DECRYPT", "vault")),
		vault: vaultConfig{
			addr:        os.Getenv("VAULT_ADDR"),
			authPath:    env("VAULT_AUTH_PATH", "kubernetes"),
			role:        os.Getenv("VAULT_ROLE"),
			tokenFile:   env("VAULT_SA_TOKEN_FILE", defaultSATokenFile),
			caCert:      os.Getenv("VAULT_CACERT"),
			transitPath: env("VAULT_TRANSIT_PATH", "transit"),
			transitKey:  env("VAULT_TRANSIT_KEY", "dkim"),
		},
	}
	var err error
	if c.cacheSize, err = positive("KEY_CACHE_SIZE", defaultCacheSize); err != nil {
		return c, err
	}
	ttl, err := positive("KEY_CACHE_TTL_SECONDS", defaultCacheTTL)
	if err != nil {
		return c, err
	}
	miss, err := positive("KEY_CACHE_MISS_TTL_SECONDS", defaultCacheMissTTL)
	if err != nil {
		return c, err
	}
	c.cacheTTL, c.cacheMissTTL = time.Duration(ttl)*time.Second, time.Duration(miss)*time.Second
	def, ok := defaultQueries[c.dbDriver]
	if !ok {
		return c, fmt.Errorf("config: DB_DRIVER %q: postgres or mysql", c.dbDriver)
	}
	c.query = env("DKIM_SQL_QUERY", def)
	if c.dbDSN == "" {
		return c, fmt.Errorf("config: DB_DSN is required")
	}
	switch c.decrypt {
	case "none":
	case "vault":
		if c.vault.addr == "" || c.vault.role == "" {
			return c, fmt.Errorf("config: KEY_DECRYPT=vault needs VAULT_ADDR and VAULT_ROLE")
		}
	default:
		return c, fmt.Errorf("config: KEY_DECRYPT %q: vault or none", c.decrypt)
	}
	return c, nil
}
