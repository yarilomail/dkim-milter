package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultListenAddr  = "0.0.0.0:8891"
	defaultMetricsAddr = "0.0.0.0:8081"
	defaultQuery       = "SELECT domain, selector, private_key_enc FROM dkim"
	defaultReload      = 60
	defaultSATokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

type config struct {
	listenAddr  string
	metricsAddr string

	dbDriver string // postgres | mysql
	dbDSN    string
	query    string

	decrypt string // vault | none
	vault   vaultConfig

	reload time.Duration
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
		query:       env("DKIM_SQL_QUERY", defaultQuery),
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
	secs, err := strconv.Atoi(env("KEY_RELOAD_SECONDS", strconv.Itoa(defaultReload)))
	if err != nil || secs < 0 {
		return c, fmt.Errorf("config: KEY_RELOAD_SECONDS %q: a whole number of seconds, 0 to load once", os.Getenv("KEY_RELOAD_SECONDS"))
	}
	c.reload = time.Duration(secs) * time.Second
	switch c.dbDriver {
	case "postgres", "mysql":
	default:
		return c, fmt.Errorf("config: DB_DRIVER %q: postgres or mysql", c.dbDriver)
	}
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
