package resolver

import (
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/baronematias81/dnscacheo/internal/cache"
	"github.com/baronematias81/dnscacheo/internal/filter"
	"github.com/baronematias81/dnscacheo/internal/policy"
	"github.com/baronematias81/dnscacheo/internal/querylog"
	"github.com/baronematias81/dnscacheo/internal/tunnel"
)

type Resolver struct {
	cache    *cache.RedisCache
	filter   *filter.Filter
	policy   *policy.Engine
	qlog     *querylog.QueryLogger
	tunnel   *tunnel.Detector
	server   *dns.Server
	client   *dns.Client
	upstreams []string
}

func New(c *cache.RedisCache, f *filter.Filter, p *policy.Engine, ql *querylog.QueryLogger, td *tunnel.Detector) *Resolver {
	return &Resolver{
		cache:     c,
		filter:    f,
		policy:    p,
		qlog:      ql,
		tunnel:    td,
		upstreams: []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"},
		client: &dns.Client{
			Timeout: 2 * time.Second,
			Net:     "udp",
		},
	}
}

func (r *Resolver) ListenAndServe() error {
	r.server = &dns.Server{
		Addr:    ":53",
		Net:     "udp",
		Handler: dns.HandlerFunc(r.handleQuery),
	}
	return r.server.ListenAndServe()
}

func (r *Resolver) handleQuery(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()
	clientIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())

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

		// 1. Análisis de tunneling (no bloqueante, corre en goroutine)
		go r.tunnel.Analyze(clientIP, q.Name, q.Qtype)

		// 2. Verificar política Zero Trust
		if !r.policy.IsAllowed(clientIP, q.Name) {
			resp.Rcode = dns.RcodeRefused
			entry.Blocked = true
			entry.BlockReason = "policy"
			entry.ResponseCode = "REFUSED"
			entry.LatencyMs = int(time.Since(start).Milliseconds())
			r.qlog.Log(entry)
			w.WriteMsg(resp)
			return
		}

		// 3. Verificar filtros (malware, ads, etc.)
		if blocked, reason := r.filter.IsBlockedWithReason(q.Name); blocked {
			resp.Rcode = dns.RcodeNameError
			entry.Blocked = true
			entry.BlockReason = reason
			entry.ResponseCode = "NXDOMAIN"
			entry.LatencyMs = int(time.Since(start).Milliseconds())
			r.qlog.Log(entry)
			w.WriteMsg(resp)
			return
		}

		// 4. Buscar en caché
		if cached := r.cache.Get(q.Name, q.Qtype); cached != nil {
			resp.Answer = append(resp.Answer, cached...)
			entry.CacheHit = true
			entry.ResponseCode = "NOERROR"
			entry.Answers = len(cached)
			entry.LatencyMs = int(time.Since(start).Milliseconds())
			r.qlog.Log(entry)
			w.WriteMsg(resp)
			return
		}

		// 5. Resolver upstream
		answers, upstream, err := r.resolveUpstream(q)
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
		entry.ResponseCode = "NOERROR"
		entry.Upstream = upstream
		entry.Answers = len(answers)
		entry.LatencyMs = int(time.Since(start).Milliseconds())
		r.qlog.Log(entry)
	}

	w.WriteMsg(resp)
}

func (r *Resolver) resolveUpstream(q dns.Question) ([]dns.RR, string, error) {
	m := new(dns.Msg)
	m.SetQuestion(q.Name, q.Qtype)
	m.RecursionDesired = true

	for _, upstream := range r.upstreams {
		resp, _, err := r.client.Exchange(m, upstream)
		if err == nil && resp.Rcode == dns.RcodeSuccess {
			return resp.Answer, upstream, nil
		}
	}
	return nil, "", dns.ErrFail
}

func (r *Resolver) Shutdown() {
	if r.server != nil {
		r.server.Shutdown()
	}
}
