// Package tunnel implementa detección de DNS tunneling mediante múltiples
// algoritmos: entropía de Shannon, labels largas, subdominios únicos por
// dominio padre, tasa de consultas y tipos de query sospechosos.
package tunnel

import (
	"math"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/baronematias81/dnscacheo/internal/metrics"
)

// AlertType identifica el algoritmo que disparó la alerta
type AlertType string

const (
	AlertHighEntropy      AlertType = "high_entropy"
	AlertLongLabel        AlertType = "long_label"
	AlertUniqueSubdomains AlertType = "unique_subdomains"
	AlertQueryRate        AlertType = "query_rate"
	AlertSuspiciousType   AlertType = "suspicious_type"
)

// Severity niveles de alerta
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Alert representa una detección de tunneling
type Alert struct {
	ClientIP     string
	Domain       string
	ParentDomain string
	QueryType    string
	AlertType    AlertType
	Severity     Severity
	Score        float64
	Details      map[string]interface{}
	Timestamp    time.Time
}

// Thresholds parámetros de detección configurables
type Thresholds struct {
	EntropyMin         float64 // entropía mínima para alerta (defecto: 3.8)
	LabelLenMin        int     // largo mínimo de label para alerta (defecto: 45)
	UniqueSubsWindow   int     // segundos de ventana para subdominios únicos (defecto: 60)
	UniqueSubsMin      int     // mínimo subdominios únicos para alerta (defecto: 40)
	QueryRateWindow    int     // segundos de ventana para tasa de consultas (defecto: 60)
	QueryRateMin       int     // mínimo consultas para alerta (defecto: 150)
}

func DefaultThresholds() Thresholds {
	return Thresholds{
		EntropyMin:       3.8,
		LabelLenMin:      45,
		UniqueSubsWindow: 60,
		UniqueSubsMin:    40,
		QueryRateWindow:  60,
		QueryRateMin:     150,
	}
}

// Tipos de query asociados con tunneling
var suspiciousQTypes = map[uint16]bool{
	dns.TypeTXT:  true,
	dns.TypeNULL: true,
	dns.TypeCNAME: true,
}

// windowEntry entrada de la ventana deslizante
type windowEntry struct {
	ts time.Time
}

// subdomainTracker rastrea subdominios únicos por dominio padre
type subdomainTracker struct {
	mu      sync.Mutex
	entries map[string]map[string]time.Time // parent -> subdominio -> último visto
}

func newSubdomainTracker() *subdomainTracker {
	t := &subdomainTracker{entries: make(map[string]map[string]time.Time)}
	go t.cleanupLoop()
	return t
}

func (t *subdomainTracker) add(parent, sub string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.entries[parent]; !ok {
		t.entries[parent] = make(map[string]time.Time)
	}
	t.entries[parent][sub] = time.Now()
	return len(t.entries[parent])
}

func (t *subdomainTracker) countRecent(parent string, window time.Duration) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	subs, ok := t.entries[parent]
	if !ok {
		return 0
	}
	cutoff := time.Now().Add(-window)
	count := 0
	for _, ts := range subs {
		if ts.After(cutoff) {
			count++
		}
	}
	return count
}

func (t *subdomainTracker) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		t.mu.Lock()
		cutoff := time.Now().Add(-10 * time.Minute)
		for parent, subs := range t.entries {
			for sub, ts := range subs {
				if ts.Before(cutoff) {
					delete(subs, sub)
				}
			}
			if len(subs) == 0 {
				delete(t.entries, parent)
			}
		}
		t.mu.Unlock()
	}
}

// queryRateTracker rastrea tasa de consultas por cliente+dominio padre
type queryRateTracker struct {
	mu      sync.Mutex
	entries map[string][]time.Time // "clientIP:parent" -> timestamps
}

func newQueryRateTracker() *queryRateTracker {
	t := &queryRateTracker{entries: make(map[string][]time.Time)}
	go t.cleanupLoop()
	return t
}

func (t *queryRateTracker) add(clientIP, parent string) int {
	key := clientIP + ":" + parent
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries[key] = append(t.entries[key], now)
	return len(t.entries[key])
}

func (t *queryRateTracker) countRecent(clientIP, parent string, window time.Duration) int {
	key := clientIP + ":" + parent
	cutoff := time.Now().Add(-window)
	t.mu.Lock()
	defer t.mu.Unlock()
	entries := t.entries[key]
	count := 0
	for _, ts := range entries {
		if ts.After(cutoff) {
			count++
		}
	}
	return count
}

func (t *queryRateTracker) cleanupLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	for range ticker.C {
		cutoff := time.Now().Add(-5 * time.Minute)
		t.mu.Lock()
		for key, entries := range t.entries {
			fresh := entries[:0]
			for _, ts := range entries {
				if ts.After(cutoff) {
					fresh = append(fresh, ts)
				}
			}
			if len(fresh) == 0 {
				delete(t.entries, key)
			} else {
				t.entries[key] = fresh
			}
		}
		t.mu.Unlock()
	}
}

// Detector es el motor principal de detección
type Detector struct {
	thresholds  Thresholds
	subTracker  *subdomainTracker
	rateTracker *queryRateTracker
	OnAlert     func(Alert) // callback cuando se detecta tunneling
}

func New(th Thresholds, onAlert func(Alert)) *Detector {
	return &Detector{
		thresholds:  th,
		subTracker:  newSubdomainTracker(),
		rateTracker: newQueryRateTracker(),
		OnAlert:     onAlert,
	}
}

// Analyze analiza una consulta DNS y dispara alertas si corresponde
func (d *Detector) Analyze(clientIP, domain string, qtype uint16) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return
	}

	parent := parentDomain(domain)
	qtypeStr := dns.TypeToString[qtype]

	// Registrar en trackers
	d.rateTracker.add(clientIP, parent)
	if parent != domain {
		d.subTracker.add(parent, domain)
	}

	// Ejecutar todos los análisis
	d.checkEntropy(clientIP, domain, parent, qtypeStr)
	d.checkLabelLength(clientIP, domain, parent, qtypeStr)
	d.checkUniqueSubdomains(clientIP, domain, parent, qtypeStr)
	d.checkQueryRate(clientIP, domain, parent, qtypeStr)
	d.checkSuspiciousType(clientIP, domain, parent, qtype, qtypeStr)
}

// checkEntropy detecta labels con entropía alta (datos codificados)
func (d *Detector) checkEntropy(clientIP, domain, parent, qtypeStr string) {
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) < 12 {
			continue // labels cortas no son indicativas
		}
		e := shannonEntropy(label)
		if e >= d.thresholds.EntropyMin {
			score := math.Min(100, (e-d.thresholds.EntropyMin)*25+50)
			d.emit(Alert{
				ClientIP:     clientIP,
				Domain:       domain,
				ParentDomain: parent,
				QueryType:    qtypeStr,
				AlertType:    AlertHighEntropy,
				Severity:     scoreToSeverity(score),
				Score:        math.Round(score*100) / 100,
				Details: map[string]interface{}{
					"label":   label,
					"entropy": math.Round(e*1000) / 1000,
					"threshold": d.thresholds.EntropyMin,
				},
			})
			return
		}
	}
}

// checkLabelLength detecta labels inusualmente largas (datos codificados en base32/64)
func (d *Detector) checkLabelLength(clientIP, domain, parent, qtypeStr string) {
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) >= d.thresholds.LabelLenMin {
			score := math.Min(100, float64(len(label)-d.thresholds.LabelLenMin)*2+60)
			d.emit(Alert{
				ClientIP:     clientIP,
				Domain:       domain,
				ParentDomain: parent,
				QueryType:    qtypeStr,
				AlertType:    AlertLongLabel,
				Severity:     scoreToSeverity(score),
				Score:        math.Round(score*100) / 100,
				Details: map[string]interface{}{
					"label":     label,
					"length":    len(label),
					"threshold": d.thresholds.LabelLenMin,
				},
			})
			return
		}
	}
}

// checkUniqueSubdomains detecta muchos subdominios únicos → exfiltración de datos
func (d *Detector) checkUniqueSubdomains(clientIP, domain, parent, qtypeStr string) {
	if parent == domain {
		return
	}
	window := time.Duration(d.thresholds.UniqueSubsWindow) * time.Second
	count := d.subTracker.countRecent(parent, window)
	if count >= d.thresholds.UniqueSubsMin {
		score := math.Min(100, float64(count-d.thresholds.UniqueSubsMin)*1.5+65)
		d.emit(Alert{
			ClientIP:     clientIP,
			Domain:       domain,
			ParentDomain: parent,
			QueryType:    qtypeStr,
			AlertType:    AlertUniqueSubdomains,
			Severity:     scoreToSeverity(score),
			Score:        math.Round(score*100) / 100,
			Details: map[string]interface{}{
				"unique_subdomains": count,
				"window_seconds":    d.thresholds.UniqueSubsWindow,
				"threshold":         d.thresholds.UniqueSubsMin,
			},
		})
	}
}

// checkQueryRate detecta tasa inusualmente alta para un dominio padre
func (d *Detector) checkQueryRate(clientIP, domain, parent, qtypeStr string) {
	window := time.Duration(d.thresholds.QueryRateWindow) * time.Second
	count := d.rateTracker.countRecent(clientIP, parent, window)
	if count >= d.thresholds.QueryRateMin {
		score := math.Min(100, float64(count-d.thresholds.QueryRateMin)*0.3+60)
		d.emit(Alert{
			ClientIP:     clientIP,
			Domain:       domain,
			ParentDomain: parent,
			QueryType:    qtypeStr,
			AlertType:    AlertQueryRate,
			Severity:     scoreToSeverity(score),
			Score:        math.Round(score*100) / 100,
			Details: map[string]interface{}{
				"queries_in_window": count,
				"window_seconds":    d.thresholds.QueryRateWindow,
				"threshold":         d.thresholds.QueryRateMin,
			},
		})
	}
}

// checkSuspiciousType detecta tipos de query poco comunes usados para tunneling
func (d *Detector) checkSuspiciousType(clientIP, domain, parent string, qtype uint16, qtypeStr string) {
	if !suspiciousQTypes[qtype] {
		return
	}
	// Solo alerta si además el dominio tiene características sospechosas
	labels := strings.Split(domain, ".")
	maxLen := 0
	for _, l := range labels {
		if len(l) > maxLen {
			maxLen = len(l)
		}
	}
	if maxLen < 20 {
		return // dominio normal, solo es TXT/NULL por razones legítimas
	}
	score := 55.0
	d.emit(Alert{
		ClientIP:     clientIP,
		Domain:       domain,
		ParentDomain: parent,
		QueryType:    qtypeStr,
		AlertType:    AlertSuspiciousType,
		Severity:     scoreToSeverity(score),
		Score:        score,
		Details: map[string]interface{}{
			"query_type":     qtypeStr,
			"max_label_len":  maxLen,
		},
	})
}

func (d *Detector) emit(a Alert) {
	a.Timestamp = time.Now()
	// Registrar en Prometheus siempre
	metrics.TunnelAlertsTotal.WithLabelValues(string(a.AlertType), string(a.Severity)).Inc()
	if d.OnAlert != nil {
		d.OnAlert(a)
	}
}

// shannonEntropy calcula la entropía de Shannon de un string
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	entropy := 0.0
	n := float64(len(s))
	for _, count := range freq {
		p := float64(count) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// parentDomain extrae el dominio padre (ej: "a.b.example.com" → "example.com")
func parentDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func scoreToSeverity(score float64) Severity {
	switch {
	case score >= 85:
		return SeverityCritical
	case score >= 70:
		return SeverityHigh
	case score >= 55:
		return SeverityMedium
	default:
		return SeverityLow
	}
}
