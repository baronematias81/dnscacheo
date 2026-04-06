package resolver

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/baronematias81/dnscacheo/internal/cache"
	"github.com/baronematias81/dnscacheo/internal/filter"
	"github.com/baronematias81/dnscacheo/internal/metrics"
	"github.com/baronematias81/dnscacheo/internal/policy"
	"github.com/baronematias81/dnscacheo/internal/querylog"
	"github.com/baronematias81/dnscacheo/internal/ratelimit"
	"github.com/baronematias81/dnscacheo/internal/tunnel"
)

// Config parámetros del resolver DNS
type Config struct {
	ListenUDP4  string   `yaml:"listen_udp4"`
	ListenTCP4  string   `yaml:"listen_tcp4"`
	IPv6Enabled bool     `yaml:"ipv6_enabled"`
	ListenUDP6  string   `yaml:"listen_udp6"`
	ListenTCP6  string   `yaml:"listen_tcp6"`
	Upstreams4  []string `yaml:"upstreams4"`
	Upstreams6  []string `yaml:"upstreams6"`
	Timeout     string   `yaml:"timeout"`
}

func DefaultConfig() Config {
	return Config{
		ListenUDP4: "0.0.0.0:53",
		ListenTCP4: "0.0.0.0:53",
		ListenUDP6: "[::]:53",
		ListenTCP6: "[::]:53",
		Upstreams4: []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"},
		Upstreams6: []string{
			"[2606:4700:4700::1111]:53",
			"[2001:4860:4860::8888]:53",
			"[2620:fe::fe]:53",
		},
		Timeout: "2s",
	}
}

type Resolver struct {
	cfg       Config
	cache     *cache.RedisCache
	filter    *filter.Filter
	policy    *policy.Engine
	qlog      *querylog.QueryLogger
	tunnel    *tunnel.Detector
	limiter   *ratelimit.Limiter
	servers   []*dns.Server
	client4   *dns.Client
	client6   *dns.Client
	mu        sync.Mutex
	// cache hit ratio tracking
	totalQ    uint64
	cacheHits uint64
	ratioMu   sync.Mutex
}

func New(cfg Config, c *cache.RedisCache, f *filter.Filter, p *policy.Engine,
	ql *querylog.QueryLogger, td *tunnel.Detector, rl *ratelimit.Limiter) *Resolver {
	return &Resolver{
		cfg:     cfg,
		cache:   c,
		filter:  f,
		policy:  p,
		qlog:    ql,
		tunnel:  td,
		limiter: rl,
		client4: &dns.Client{Net: "udp", Timeout: 2 * time.Second},
		client6: &dns.Client{Net: "udp6", Timeout: 2 * time.Second},
	}
}

// Handler devuelve el dns.Handler compartido con DoT y DoH
func (r *Resolver) Handler() dns.Handler {
	return dns.HandlerFunc(r.handleQuery)
}

// ListenAndServe inicia todos los listeners configurados
func (r *Resolver) ListenAndServe() error {
	addrs := []struct{ net, addr string }{
		{"udp", r.cfg.ListenUDP4},
		{"tcp", r.cfg.ListenTCP4},
	}
	if r.cfg.IPv6Enabled {
		addrs = append(addrs,
			struct{ net, addr string }{"udp6", r.cfg.ListenUDP6},
			struct{ net, addr string }{"tcp6", r.cfg.ListenTCP6},
		)
	}

	errCh := make(chan error, len(addrs))
	for _, a := range addrs {
		srv := &dns.Server{Addr: a.addr, Net: a.net, Handler: r.Handler()}
		r.mu.Lock()
		r.servers = append(r.servers, srv)
		r.mu.Unlock()

		go func(s *dns.Server) {
			if err := s.ListenAndServe(); err != nil {
				errCh <- fmt.Errorf("%s %s: %w", s.Net, s.Addr, err)
			}
		}(srv)
	}
	return <-errCh
}

func (r *Resolver) handleQuery(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()

	remoteStr := w.RemoteAddr().String()
	clientIP, _, err := net.SplitHostPort(remoteStr)
	if err != nil {
		clientIP = remoteStr
	}

	ipv6 := isIPv6(clientIP)
	protocol := protocolFromNetwork(w.RemoteAddr().Network())

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true

	for _, q := range req.Question {
		qtype := dns.TypeToString[q.Qtype]
		entry := querylog.Entry{
			Timestamp: start,
			ClientIP:  clientIP,
			Domain:    q.Name,
			QueryType: qtype,
		}

		// 1. Rate limiting
		if allowed, reason := r.limiter.Allow(clientIP); !allowed {
			resp.Rcode = dns.RcodeRefused
			entry.Blocked, entry.BlockReason, entry.ResponseCode = true, reason, "REFUSED"
			entry.LatencyMs = int(time.Since(start).Milliseconds())
			r.qlog.Log(entry)

			metrics.BlockedTotal.WithLabelValues("ratelimit").Inc()
			metrics.RateLimitedTotal.Inc()
			metrics.QueriesTotal.WithLabelValues(qtype, "REFUSED", protocol).Inc()
			w.WriteMsg(resp)
			return
		}

		// 2. Análisis de tunneling (no bloqueante)
		go func(ip, domain string, qt uint16) {
			r.tunnel.Analyze(ip, domain, qt)
		}(clientIP, q.Name, q.Qtype)

		// 3. Política Zero Trust
		if !r.policy.IsAllowed(clientIP, q.Name) {
			resp.Rcode = dns.RcodeRefused
			entry.Blocked, entry.BlockReason, entry.ResponseCode = true, "policy", "REFUSED"
			entry.LatencyMs = int(time.Since(start).Milliseconds())
			r.qlog.Log(entry)

			metrics.BlockedTotal.WithLabelValues("policy").Inc()
			metrics.QueriesTotal.WithLabelValues(qtype, "REFUSED", protocol).Inc()
			w.WriteMsg(resp)
			return
		}

		// 4. Filtros
		if blocked, reason := r.filter.IsBlockedWithReason(q.Name); blocked {
			resp.Rcode = dns.RcodeNameError
			entry.Blocked, entry.BlockReason, entry.ResponseCode = true, reason, "NXDOMAIN"
			entry.LatencyMs = int(time.Since(start).Milliseconds())
			r.qlog.Log(entry)

			metrics.BlockedTotal.WithLabelValues(reason).Inc()
			metrics.QueriesTotal.WithLabelValues(qtype, "NXDOMAIN", protocol).Inc()
			w.WriteMsg(resp)
			return
		}

		// 5. Caché
		if cached := r.cache.Get(q.Name, q.Qtype); cached != nil {
			resp.Answer = append(resp.Answer, cached...)
			entry.CacheHit, entry.ResponseCode, entry.Answers = true, "NOERROR", len(cached)
			dur := time.Since(start).Seconds()
			entry.LatencyMs = int(dur * 1000)
			r.qlog.Log(entry)

			metrics.RecordQuery(qtype, "NOERROR", protocol, "cache", dur, ipv6)
			r.updateCacheRatio(true)
			w.WriteMsg(resp)
			return
		}

		// 6. Upstream
		answers, upstream, upstreamDur, err := r.resolveUpstream(q, ipv6)
		dur := time.Since(start).Seconds()
		if err != nil {
			resp.Rcode = dns.RcodeServerFailure
			entry.ResponseCode = "SERVFAIL"
			entry.LatencyMs = int(dur * 1000)
			r.qlog.Log(entry)

			metrics.QueriesTotal.WithLabelValues(qtype, "SERVFAIL", protocol).Inc()
			w.WriteMsg(resp)
			return
		}

		// 7. Guardar en caché
		r.cache.Set(q.Name, q.Qtype, answers)

		resp.Answer = append(resp.Answer, answers...)
		entry.ResponseCode, entry.Upstream, entry.Answers = "NOERROR", upstream, len(answers)
		entry.LatencyMs = int(dur * 1000)
		r.qlog.Log(entry)

		metrics.RecordQuery(qtype, "NOERROR", protocol, "upstream", dur, ipv6)
		metrics.UpstreamQueriesTotal.WithLabelValues(upstream).Inc()
		metrics.UpstreamLatency.WithLabelValues(upstream).Observe(upstreamDur)
		r.updateCacheRatio(false)
	}

	// Actualizar gauge de clientes activos
	metrics.ActiveClients.Set(float64(r.limiter.Stats()))

	w.WriteMsg(resp)
}

func (r *Resolver) resolveUpstream(q dns.Question, preferIPv6 bool) ([]dns.RR, string, float64, error) {
	m := new(dns.Msg)
	m.SetQuestion(q.Name, q.Qtype)
	m.RecursionDesired = true

	type attempt struct {
		servers []string
		client  *dns.Client
	}

	var attempts []attempt
	if preferIPv6 && len(r.cfg.Upstreams6) > 0 {
		attempts = []attempt{{r.cfg.Upstreams6, r.client6}, {r.cfg.Upstreams4, r.client4}}
	} else {
		attempts = []attempt{{r.cfg.Upstreams4, r.client4}, {r.cfg.Upstreams6, r.client6}}
	}

	for _, a := range attempts {
		for _, upstream := range a.servers {
			start := time.Now()
			resp, _, err := a.client.Exchange(m, upstream)
			dur := time.Since(start).Seconds()
			if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
				return resp.Answer, upstream, dur, nil
			}
			if err != nil {
				metrics.UpstreamErrorsTotal.WithLabelValues(upstream).Inc()
			}
		}
	}
	return nil, "", 0, dns.ErrFail
}

func (r *Resolver) updateCacheRatio(hit bool) {
	r.ratioMu.Lock()
	r.totalQ++
	if hit {
		r.cacheHits++
	}
	ratio := float64(r.cacheHits) / float64(r.totalQ)
	r.ratioMu.Unlock()
	metrics.CacheHitRatio.Set(ratio)
}

func (r *Resolver) Shutdown() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.servers {
		s.Shutdown()
	}
}

func isIPv6(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && ip.To4() == nil
}

func protocolFromNetwork(network string) string {
	switch network {
	case "udp6":
		return "udp6"
	case "tcp6":
		return "tcp6"
	case "tcp":
		return "tcp4"
	default:
		return "udp4"
	}
}
