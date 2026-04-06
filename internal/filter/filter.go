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
	blocked map[string]bool
	mu      sync.RWMutex
	enabled bool
}

func New(cfg interface{}) *Filter {
	f := &Filter{
		blocked: make(map[string]bool),
		enabled: true,
	}
	go f.loadBlocklists()
	return f
}

func (f *Filter) IsBlocked(domain string) bool {
	if !f.enabled {
		return false
	}

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	f.mu.RLock()
	defer f.mu.RUnlock()

	// Verificar dominio exacto
	if f.blocked[domain] {
		return true
	}

	// Verificar dominios padre
	parts := strings.Split(domain, ".")
	for i := range parts {
		parent := strings.Join(parts[i:], ".")
		if f.blocked[parent] {
			return true
		}
	}

	return false
}

func (f *Filter) AddDomain(domain string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blocked[strings.ToLower(domain)] = true
}

func (f *Filter) loadBlocklists() {
	for _, url := range defaultBlocklists {
		f.loadFromURL(url)
	}
}

func (f *Filter) loadFromURL(url string) {
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
			f.blocked[strings.ToLower(domain)] = true
		}
	}
}
