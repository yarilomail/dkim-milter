package main

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	signResults = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dkim_messages_total", Help: "Messages seen, by result: signed, no_key, no_from, tempfail, error.",
	}, []string{"result"})
	keysLoaded = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dkim_keys_loaded", Help: "Domains with a key in the cache.",
	})
	cacheLookups = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dkim_key_cache_lookups_total", Help: "Key lookups, by result: hit, negative_hit (cached as keyless), miss.",
	}, []string{"result"})
	keyFetchErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dkim_key_fetch_errors_total", Help: "Key fetches that failed, by stage: db, vault, parse.",
	}, []string{"stage"})
)

func metricsMux(ready func() bool) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready() {
			http.Error(w, "database or Vault not reached yet", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return mux
}
