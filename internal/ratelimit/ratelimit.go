// Package ratelimit implementa un rate limiter por IP usando token bucket.
// Cada cliente tiene su propio bucket; se pueden definir límites globales
// o personalizados por IP/CIDR desde la configuración.
package ratelimit

import (
	"net"
	"sync"
	"time"
)

// Config parámetros globales del rate limiter
type Config struct {
	Enabled          bool    `yaml:"enabled"`
	GlobalRate       float64 `yaml:"global_rate"`        // queries/segundo por defecto
	GlobalBurst      int     `yaml:"global_burst"`       // ráfaga máxima por defecto
	PerClientRates   []Rule  `yaml:"per_client_rates"`   // reglas por IP/CIDR
	CleanupInterval  int     `yaml:"cleanup_interval"`   // segundos entre cleanup (default 60)
	IdleTimeout      int     `yaml:"idle_timeout"`       // segundos sin actividad para expirar (default 300)
}

// Rule regla de rate limit para una IP o subred específica
type Rule struct {
	CIDR  string  `yaml:"cidr"`
	Rate  float64 `yaml:"rate"`  // queries/segundo
	Burst int     `yaml:"burst"` // ráfaga máxima
}

func DefaultConfig() Config {
	return Config{
		Enabled:         true,
		GlobalRate:      100,  // 100 q/s por cliente
		GlobalBurst:     200,  // ráfaga de hasta 200
		CleanupInterval: 60,
		IdleTimeout:     300,
	}
}

// bucket implementa el token bucket para un cliente
type bucket struct {
	tokens   float64
	rate     float64 // tokens por segundo
	burst    float64 // capacidad máxima
	lastSeen time.Time
	mu       sync.Mutex
}

func newBucket(rate float64, burst int) *bucket {
	return &bucket{
		tokens:   float64(burst),
		rate:     rate,
		burst:    float64(burst),
		lastSeen: time.Now(),
	}
}

// Allow consume un token. Retorna true si la consulta está permitida.
func (b *bucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.lastSeen = now

	// Recargar tokens según el tiempo transcurrido
	b.tokens += elapsed * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Limiter gestiona los buckets de todos los clientes
type Limiter struct {
	cfg     Config
	buckets map[string]*bucket
	rules   []parsedRule
	mu      sync.RWMutex
}

type parsedRule struct {
	subnet *net.IPNet
	rate   float64
	burst  int
}

func New(cfg Config) *Limiter {
	l := &Limiter{
		cfg:     cfg,
		buckets: make(map[string]*bucket),
	}

	for _, r := range cfg.PerClientRates {
		_, subnet, err := net.ParseCIDR(r.CIDR)
		if err != nil {
			continue
		}
		burst := r.Burst
		if burst == 0 {
			burst = int(r.Rate * 2)
		}
		l.rules = append(l.rules, parsedRule{subnet: subnet, rate: r.Rate, burst: burst})
	}

	go l.cleanupLoop()
	return l
}

// Allow verifica si el cliente puede hacer la consulta.
// Retorna (permitido, límite aplicado)
func (l *Limiter) Allow(clientIP string) (bool, string) {
	if !l.cfg.Enabled {
		return true, ""
	}

	rate, burst := l.rateForIP(clientIP)
	b := l.getOrCreate(clientIP, rate, burst)
	if !b.Allow() {
		return false, "ratelimit"
	}
	return true, ""
}

// rateForIP devuelve el rate/burst para una IP según reglas configuradas
func (l *Limiter) rateForIP(clientIP string) (float64, int) {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return l.cfg.GlobalRate, l.cfg.GlobalBurst
	}

	for _, r := range l.rules {
		if r.subnet.Contains(ip) {
			return r.rate, r.burst
		}
	}
	return l.cfg.GlobalRate, l.cfg.GlobalBurst
}

func (l *Limiter) getOrCreate(clientIP string, rate float64, burst int) *bucket {
	l.mu.RLock()
	b, ok := l.buckets[clientIP]
	l.mu.RUnlock()

	if ok {
		return b
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	// Double-check después de adquirir write lock
	if b, ok = l.buckets[clientIP]; ok {
		return b
	}
	b = newBucket(rate, burst)
	l.buckets[clientIP] = b
	return b
}

// Stats devuelve el número de clientes rastreados actualmente
func (l *Limiter) Stats() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.buckets)
}

func (l *Limiter) cleanupLoop() {
	interval := time.Duration(l.cfg.CleanupInterval) * time.Second
	if interval == 0 {
		interval = 60 * time.Second
	}
	idle := time.Duration(l.cfg.IdleTimeout) * time.Second
	if idle == 0 {
		idle = 300 * time.Second
	}

	ticker := time.NewTicker(interval)
	for range ticker.C {
		cutoff := time.Now().Add(-idle)
		l.mu.Lock()
		for ip, b := range l.buckets {
			b.mu.Lock()
			if b.lastSeen.Before(cutoff) {
				delete(l.buckets, ip)
			}
			b.mu.Unlock()
		}
		l.mu.Unlock()
	}
}
