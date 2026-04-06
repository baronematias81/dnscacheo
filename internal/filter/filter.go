package filter

import (
	"bufio"
	"net/http"
	"strings"
	"sync"
)

// Listas públicas de bloqueo (actualizables)
var defaultBlocklists = map[string]string{
	"malware": "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt",
	"ads":     "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
}

type Filter struct {
	blocked map[string]string // dominio -> razón (malware, ads, etc.)
	mu      sync.RWMutex
	enabled bool
}

func New(enabled bool) *Filter {
	f := &Filter{
		blocked: make(map[string]string),
		enabled: enabled,
	}
	go f.loadBlocklists()
	return f
}

func (f *Filter) IsBlocked(domain string) bool {
	blocked, _ := f.IsBlockedWithReason(domain)
	return blocked
}

func (f *Filter) IsBlockedWithReason(domain string) (bool, string) {
	if !f.enabled {
		return false, ""
	}

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	f.mu.RLock()
	defer f.mu.RUnlock()

	// Verificar dominio exacto
	if reason, ok := f.blocked[domain]; ok {
		return true, reason
	}

	// Verificar dominios padre
	parts := strings.Split(domain, ".")
	for i := range parts {
		parent := strings.Join(parts[i:], ".")
		if reason, ok := f.blocked[parent]; ok {
			return true, reason
		}
	}

	return false, ""
}

func (f *Filter) AddDomain(domain, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blocked[strings.ToLower(domain)] = reason
}

func (f *Filter) loadBlocklists() {
	for category, url := range defaultBlocklists {
		f.loadFromURL(url, category)
	}
}

func (f *Filter) loadFromURL(url, category string) {
	resp, err := http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	f.mu.Lock()
	defer f.mu.Unlock()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Formato "0.0.0.0 dominio.com" o solo "dominio.com"
		fields := strings.Fields(line)
		domain := ""
		if len(fields) == 2 {
			domain = fields[1]
		} else if len(fields) == 1 {
			domain = fields[0]
		}
		if domain != "" && domain != "localhost" {
			f.blocked[strings.ToLower(domain)] = category
		}
	}
}
