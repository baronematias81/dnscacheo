package resolver

import (
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/baronematias81/dnscacheo/internal/cache"
	"github.com/baronematias81/dnscacheo/internal/filter"
	"github.com/baronematias81/dnscacheo/internal/policy"
)

type Resolver struct {
	config   *Config
	cache    *cache.RedisCache
	filter   *filter.Filter
	policy   *policy.Engine
	server   *dns.Server
	client   *dns.Client
}

func New(cfg interface{}, c *cache.RedisCache, f *filter.Filter, p *policy.Engine, log interface{}) *Resolver {
	return &Resolver{
		cache:  c,
		filter: f,
		policy: p,
		client: &dns.Client{
			Timeout: 2 * time.Second,
			Net:     "udp",
		},
	}
}

func (r *Resolver) ListenAndServe() {
	r.server = &dns.Server{
		Addr:    ":53",
		Net:     "udp",
		Handler: dns.HandlerFunc(r.handleQuery),
	}
	r.server.ListenAndServe()
}

func (r *Resolver) handleQuery(w dns.ResponseWriter, req *dns.Msg) {
	clientIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true

	for _, q := range req.Question {
		// 1. Verificar política Zero Trust del cliente
		if !r.policy.IsAllowed(clientIP, q.Name) {
			resp.Rcode = dns.RcodeRefused
			w.WriteMsg(resp)
			return
		}

		// 2. Verificar filtros (malware, ads, etc.)
		if r.filter.IsBlocked(q.Name) {
			resp.Rcode = dns.RcodeNameError
			w.WriteMsg(resp)
			return
		}

		// 3. Buscar en caché
		if cached := r.cache.Get(q.Name, q.Qtype); cached != nil {
			resp.Answer = append(resp.Answer, cached...)
			w.WriteMsg(resp)
			return
		}

		// 4. Resolver upstream
		answers, err := r.resolveUpstream(q)
		if err != nil {
			resp.Rcode = dns.RcodeServerFailure
			w.WriteMsg(resp)
			return
		}

		// 5. Guardar en caché
		r.cache.Set(q.Name, q.Qtype, answers)
		resp.Answer = append(resp.Answer, answers...)
	}

	w.WriteMsg(resp)
}

func (r *Resolver) resolveUpstream(q dns.Question) ([]dns.RR, error) {
	upstreams := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}

	m := new(dns.Msg)
	m.SetQuestion(q.Name, q.Qtype)
	m.RecursionDesired = true

	for _, upstream := range upstreams {
		resp, _, err := r.client.Exchange(m, upstream)
		if err == nil && resp.Rcode == dns.RcodeSuccess {
			return resp.Answer, nil
		}
	}
	return nil, dns.ErrFail
}

func (r *Resolver) Shutdown() {
	if r.server != nil {
		r.server.Shutdown()
	}
}
