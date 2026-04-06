package policy

import (
	"net"
	"strings"
)

// ClientPolicy define las reglas Zero Trust para un cliente
type ClientPolicy struct {
	ClientIP    string   `json:"client_ip"`
	AllowAll    bool     `json:"allow_all"`
	Whitelist   []string `json:"whitelist"`
	Blacklist   []string `json:"blacklist"`
	BlockAdult  bool     `json:"block_adult"`
	BlockGaming bool     `json:"block_gaming"`
	RateLimit   int      `json:"rate_limit"` // consultas por segundo
}

type Engine struct {
	policies      map[string]*ClientPolicy
	defaultPolicy string // "allow" | "block"
}

func New(defaultPolicy string) *Engine {
	if defaultPolicy == "" {
		defaultPolicy = "allow"
	}
	return &Engine{
		policies:      make(map[string]*ClientPolicy),
		defaultPolicy: defaultPolicy,
	}
}

// IsAllowed verifica si el cliente puede resolver el dominio
func (e *Engine) IsAllowed(clientIP, domain string) bool {
	p := e.getPolicy(clientIP)

	if p == nil {
		return e.defaultPolicy == "allow"
	}

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	// Verificar lista negra del cliente
	for _, blocked := range p.Blacklist {
		if matchDomain(domain, blocked) {
			return false
		}
	}

	// Si tiene lista blanca, solo permite esos dominios
	if len(p.Whitelist) > 0 {
		for _, allowed := range p.Whitelist {
			if matchDomain(domain, allowed) {
				return true
			}
		}
		return false
	}

	return p.AllowAll
}

func (e *Engine) getPolicy(clientIP string) *ClientPolicy {
	if p, ok := e.policies[clientIP]; ok {
		return p
	}
	for cidr, p := range e.policies {
		if _, subnet, err := net.ParseCIDR(cidr); err == nil {
			if subnet.Contains(net.ParseIP(clientIP)) {
				return p
			}
		}
	}
	return nil
}

// SetPolicy asigna una política a un cliente o subred
func (e *Engine) SetPolicy(clientIP string, p *ClientPolicy) {
	e.policies[clientIP] = p
}

// GetPolicies retorna todas las políticas
func (e *Engine) GetPolicies() map[string]*ClientPolicy {
	return e.policies
}

func matchDomain(domain, pattern string) bool {
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return strings.HasSuffix(domain, suffix)
	}
	return domain == pattern
}
