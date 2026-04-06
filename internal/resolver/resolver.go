package resolver

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/baronematias81/dnscacheo/internal/cache"
	"github.com/baronematias81/dnscacheo/internal/filter"
	"github.com/baronematias81/dnscacheo/internal/policy"
	"github.com/baronematias81/dnscacheo/internal/querylog"
	"github.com/baronematias81/dnscacheo/internal/tunnel"
)

// Config parámetros del resolver DNS
type Config struct {
	// IPv4
	ListenUDP4 string `yaml:"listen_udp4"` // default: "0.0.0.0:53"
	ListenTCP4 string `yaml:"listen_tcp4"` // default: "0.0.0.0:53"

	// IPv6
	IPv6Enabled bool   `yaml:"ipv6_enabled"`
	ListenUDP6  string `yaml:"listen_udp6"` // default: "[::]:53"
	ListenTCP6  string `yaml:"listen_tcp6"` // default: "[::]:53"

	// Upstreams
	Upstreams4 []string `yaml:"upstreams4"` // IPv4 upstreams
	Upstreams6 []string `yaml:"upstreams6"` // IPv6 upstreams
	Timeout    string   `yaml:"timeout"`
}

func DefaultConfig() Config {
	return Config{
		ListenUDP4: "0.0.0.0:53",
		ListenTCP4: "0.0.0.0:53",
		ListenUDP6: "[::]:53",
		ListenTCP6: "[::]:53",
		Upstreams4: []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"},
		Upstreams6: []string{
			"[2606:4700:4700::1111]:53", // Cloudflare IPv6
			"[2001:4860:4860::8888]:53", // Google IPv6
			"[2620:fe::fe]:53",          // Quad9 IPv6
		},
		Timeout: "2s",
	}
}

type Resolver struct {
	cfg      Config
	cache    *cache.RedisCache
	filter   *filter.Filter
	policy   *policy.Engine
	qlog     *querylog.QueryLogger
	tunnel   *tunnel.Detector
	servers  []*dns.Server
	client4  *dns.Client
	client6  *dns.Client
	mu       sync.Mutex
}

func New(cfg Config, c *cache.RedisCache, f *filter.Filter, p *policy.Engine, ql *querylog.QueryLogger, td *tunnel.Detector) *Resolver {
	return &Resolver{
		cfg:    cfg,
		cache:  c,
		filter: f,
		policy: p,
		qlog:   ql,
		tunnel: td,
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
		srv := &dns.Server{
			Addr:    a.addr,
			Net:     a.net,
			Handler: r.Handler(),
		}
		r.mu.Lock()
		r.servers = append(r.servers, srv)
		r.mu.Unlock()

		go func(s *dns.Server) {
			if err := s.ListenAndServe(); err != nil {
				errCh <- fmt.Errorf("%s %s: %w", s.Net, s.Addr, err)
			}
		}(srv)
	}

	// Bloquear hasta el primer error (o Shutdown)
	return <-errCh
}

func (r *Resolver) handleQuery(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()

	// Extraer IP del cliente — soporta IPv4 e IPv6
	remoteStr := w.RemoteAddr().String()
	clientIP, _, err := net.SplitHostPort(remoteStr)
	if err != nil {
		clientIP = remoteStr // fallback para direcciones sin puerto
	}

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true

	for _, q := range req.Question {
		entry := querylog.Entry{
			Timestamp: start,
			ClientIP:  clientIP,
			Domain:    q.Name,
			QueryType: dns.TypeToString[q.Qtype],
		}

		// 1. Análisis de tunneling (no bloqueante)
		go r.tunnel.Analyze(clientIP, q.Name, q.Qtype)

		// 2. Política Zero Trust
		if !r.policy.IsAllowed(clientIP, q.Name) {
			resp.Rcode = dns.RcodeRefused
			entry.Blocked, entry.BlockReason, entry.ResponseCode = true, "policy", "REFUSED"
			entry.LatencyMs = int(time.Since(start).Milliseconds())
			r.qlog.Log(entry)
			w.WriteMsg(resp)
			return
		}

		// 3. Filtros
		if blocked, reason := r.filter.IsBlockedWithReason(q.Name); blocked {
			resp.Rcode = dns.RcodeNameError
			entry.Blocked, entry.BlockReason, entry.ResponseCode = true, reason, "NXDOMAIN"
			entry.LatencyMs = int(time.Since(start).Milliseconds())
			r.qlog.Log(entry)
			w.WriteMsg(resp)
			return
		}

		// 4. Caché
		if cached := r.cache.Get(q.Name, q.Qtype); cached != nil {
			resp.Answer = append(resp.Answer, cached...)
			entry.CacheHit, entry.ResponseCode, entry.Answers = true, "NOERROR", len(cached)
			entry.LatencyMs = int(time.Since(start).Milliseconds())
			r.qlog.Log(entry)
			w.WriteMsg(resp)
			return
		}

		// 5. Upstream — preferir IPv6 si el cliente es IPv6
		answers, upstream, err := r.resolveUpstream(q, isIPv6(clientIP))
		if err != nil {
			resp.Rcode = dns.RcodeServerFailure
			entry.ResponseCode = "SERVFAIL"
			entry.LatencyMs = int(time.Since(start).Milliseconds())
			r.qlog.Log(entry)
			w.WriteMsg(resp)
			return
		}

		// 6. Guardar en caché
		r.cache.Set(q.Name, q.Qtype, answers)

		resp.Answer = append(resp.Answer, answers...)
		entry.ResponseCode, entry.Upstream, entry.Answers = "NOERROR", upstream, len(answers)
		entry.LatencyMs = int(time.Since(start).Milliseconds())
		r.qlog.Log(entry)
	}

	w.WriteMsg(resp)
}

// resolveUpstream intenta upstreams IPv6 primero si preferIPv6=true,
// luego cae a IPv4 como fallback.
func (r *Resolver) resolveUpstream(q dns.Question, preferIPv6 bool) ([]dns.RR, string, error) {
	m := new(dns.Msg)
	m.SetQuestion(q.Name, q.Qtype)
	m.RecursionDesired = true

	type attempt struct {
		servers []string
		client  *dns.Client
	}

	var attempts []attempt
	if preferIPv6 && len(r.cfg.Upstreams6) > 0 {
		attempts = []attempt{
			{r.cfg.Upstreams6, r.client6},
			{r.cfg.Upstreams4, r.client4},
		}
	} else {
		attempts = []attempt{
			{r.cfg.Upstreams4, r.client4},
			{r.cfg.Upstreams6, r.client6},
		}
	}

	for _, a := range attempts {
		for _, upstream := range a.servers {
			resp, _, err := a.client.Exchange(m, upstream)
			if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
				return resp.Answer, upstream, nil
			}
		}
	}
	return nil, "", dns.ErrFail
}

func (r *Resolver) Shutdown() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.servers {
		s.Shutdown()
	}
}

// isIPv6 devuelve true si la IP es una dirección IPv6
func isIPv6(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && ip.To4() == nil
}
