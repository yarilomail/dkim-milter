package main

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	signResults = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dkim_messages_total", Help: "Messages seen, by result: signed, no_key, no_from, error.",
	}, []string{"result"})
	keysLoaded = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dkim_keys_loaded", Help: "Domains with a usable key in memory.",
	})
	keysLoadedAt = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dkim_keys_loaded_timestamp_seconds", Help: "Unix time of the last successful key load.",
	})
	keyLoadErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dkim_key_load_errors_total", Help: "Key loads that failed as a whole; the previous keys stay in use.",
	})
	keyRowErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dkim_key_row_errors_total", Help: "Keys that did not decrypt or parse; their domains are not signed.",
	})
)

func metricsMux(ready func() bool) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready() {
			http.Error(w, "keys not loaded", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return mux
}
