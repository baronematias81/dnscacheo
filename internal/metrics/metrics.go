// Package metrics define y registra todas las métricas Prometheus de dnscacheo.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// ── Consultas ────────────────────────────────────────────
	QueriesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_queries_total",
		Help: "Total de consultas DNS procesadas",
	}, []string{"query_type", "response_code", "protocol"}) // protocol: udp4|tcp4|udp6|tcp6|dot|doh

	QueryDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "dns_query_duration_seconds",
		Help:    "Latencia de consultas DNS en segundos",
		Buckets: []float64{.001, .005, .010, .025, .050, .100, .250, .500, 1.0},
	}, []string{"query_type", "source"}) // source: cache|upstream|blocked

	// ── Caché ────────────────────────────────────────────────
	CacheHitsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_cache_hits_total",
		Help: "Consultas resueltas desde el caché",
	})

	CacheMissesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_cache_misses_total",
		Help: "Consultas que no encontraron entrada en caché",
	})

	CacheHitRatio = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dns_cache_hit_ratio",
		Help: "Ratio actual de cache hits (0.0 - 1.0)",
	})

	// ── Bloqueos ────────────────────────────────────────────
	BlockedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_blocked_queries_total",
		Help: "Consultas bloqueadas por categoría",
	}, []string{"reason"}) // reason: malware|ads|policy|ratelimit

	// ── Upstreams ────────────────────────────────────────────
	UpstreamQueriesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_upstream_queries_total",
		Help: "Consultas enviadas a cada upstream",
	}, []string{"upstream"})

	UpstreamErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_upstream_errors_total",
		Help: "Errores por upstream",
	}, []string{"upstream"})

	UpstreamLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "dns_upstream_latency_seconds",
		Help:    "Latencia de respuesta de upstreams",
		Buckets: []float64{.005, .010, .025, .050, .100, .250, .500, 1.0, 2.0},
	}, []string{"upstream"})

	// ── Clientes ─────────────────────────────────────────────
	ActiveClients = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dns_active_clients",
		Help: "Clientes rastreados en el rate limiter",
	})

	RateLimitedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_rate_limited_total",
		Help: "Consultas rechazadas por rate limiting",
	})

	// ── Tunneling ────────────────────────────────────────────
	TunnelAlertsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_tunnel_alerts_total",
		Help: "Alertas de DNS tunneling generadas",
	}, []string{"alert_type", "severity"})

	// ── IPv6 ─────────────────────────────────────────────────
	IPv6QueriesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_ipv6_queries_total",
		Help: "Consultas recibidas por IPv6",
	})

	IPv4QueriesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dns_ipv4_queries_total",
		Help: "Consultas recibidas por IPv4",
	})

	// ── Sistema ──────────────────────────────────────────────
	BuildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dns_build_info",
		Help: "Información de la versión del servidor",
	}, []string{"version", "empresa"})
)

func init() {
	BuildInfo.WithLabelValues("1.0.0", "Grupo Barone SRL").Set(1)
}

// StartServer inicia el servidor HTTP de métricas en la dirección indicada
func StartServer(addr string) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	http.ListenAndServe(addr, mux)
}

// RecordQuery registra todas las métricas asociadas a una consulta completada
func RecordQuery(queryType, responseCode, protocol, source string, durationSecs float64, isIPv6 bool) {
	QueriesTotal.WithLabelValues(queryType, responseCode, protocol).Inc()
	QueryDuration.WithLabelValues(queryType, source).Observe(durationSecs)

	if isIPv6 {
		IPv6QueriesTotal.Inc()
	} else {
		IPv4QueriesTotal.Inc()
	}

	switch source {
	case "cache":
		CacheHitsTotal.Inc()
	case "upstream":
		CacheMissesTotal.Inc()
	}
}
