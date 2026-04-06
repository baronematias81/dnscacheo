package policy

import (
	"net"
	"strings"
)

// ClientPolicy define las reglas Zero Trust para un cliente
type ClientPolicy struct {
	ClientIP    string
	AllowAll    bool
	Whitelist   []string
	Blacklist   []string
	BlockAdult  bool
	BlockGaming bool
	RateLimit   int // consultas por segundo
}

type Engine struct {
	policies map[string]*ClientPolicy // clave: IP del cliente
	defaults ClientPolicy
}

func New(cfg interface{}, db interface{}) *Engine {
	return &Engine{
		policies: make(map[string]*ClientPolicy),
		defaults: ClientPolicy{
			AllowAll:  true,
			RateLimit: 100,
		},
	}
}

// IsAllowed verifica si el cliente puede resolver el dominio
func (e *Engine) IsAllowed(clientIP, domain string) bool {
	policy := e.getPolicy(clientIP)

	if policy.AllowAll && len(policy.Blacklist) == 0 {
		return true
	}

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	// Verificar lista negra del cliente
	for _, blocked := range policy.Blacklist {
		if matchDomain(domain, blocked) {
			return false
		}
	}

	// Si tiene lista blanca, solo permite esos dominios
	if len(policy.Whitelist) > 0 {
		for _, allowed := range policy.Whitelist {
			if matchDomain(domain, allowed) {
				return true
			}
		}
		return false
	}

	return true
}

func (e *Engine) getPolicy(clientIP string) *ClientPolicy {
	// Buscar política exacta por IP
	if p, ok := e.policies[clientIP]; ok {
		return p
	}

	// Buscar por subred
	for cidr, p := range e.policies {
		if _, subnet, err := net.ParseCIDR(cidr); err == nil {
			if subnet.Contains(net.ParseIP(clientIP)) {
				return p
			}
		}
	}

	return &e.defaults
}

// SetPolicy asigna una política a un cliente o subred
func (e *Engine) SetPolicy(clientIP string, p *ClientPolicy) {
	e.policies[clientIP] = p
}

func matchDomain(domain, pattern string) bool {
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return strings.HasSuffix(domain, suffix)
	}
	return domain == pattern
}
