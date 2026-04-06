// Package doh implementa un servidor DNS over HTTPS (RFC 8484).
// Soporta tanto GET (?dns=<base64url>) como POST (body en wire format).
// Content-Type: application/dns-message en ambos casos.
package doh

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Config parámetros del servidor DoH
type Config struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`  // default: "0.0.0.0:443"
	Path    string `yaml:"path"`    // default: "/dns-query"
	// Si ListenPlain está habilitado, también escucha HTTP en otro puerto
	// para clientes que ya tienen DoH configurado con proxy TLS externo
	ListenPlain string `yaml:"listen_plain"` // ej: "0.0.0.0:8053" (sin TLS)
}

// Server es el servidor DoH
type Server struct {
	cfg     Config
	tlsCfg  *tls.Config
	handler dns.Handler
	https   *http.Server
	plain   *http.Server
}

func New(cfg Config, tlsCfg *tls.Config, handler dns.Handler) *Server {
	if cfg.Listen == "" {
		cfg.Listen = "0.0.0.0:443"
	}
	if cfg.Path == "" {
		cfg.Path = "/dns-query"
	}
	return &Server{cfg: cfg, tlsCfg: tlsCfg, handler: handler}
}

// ListenAndServe inicia el servidor HTTPS (y opcionalmente el HTTP plano)
func (s *Server) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc(s.cfg.Path, s.serveDNS)

	s.https = &http.Server{
		Addr:         s.cfg.Listen,
		Handler:      mux,
		TLSConfig:    s.tlsCfg,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	// Servidor HTTP plano (opcional, para terminar TLS en un proxy externo)
	if s.cfg.ListenPlain != "" {
		plainMux := http.NewServeMux()
		plainMux.HandleFunc(s.cfg.Path, s.serveDNS)
		s.plain = &http.Server{
			Addr:         s.cfg.ListenPlain,
			Handler:      plainMux,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		}
		go s.plain.ListenAndServe()
	}

	// Necesitamos que el TLSConfig ya tenga el cert cargado, así que
	// usamos ListenAndServeTLS con strings vacíos (el cert viene en TLSConfig)
	ln, err := tls.Listen("tcp", s.cfg.Listen, s.tlsCfg)
	if err != nil {
		return err
	}
	return s.https.Serve(ln)
}

func (s *Server) serveDNS(w http.ResponseWriter, r *http.Request) {
	var msgBuf []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		// GET /dns-query?dns=<base64url>
		b64 := r.URL.Query().Get("dns")
		if b64 == "" {
			http.Error(w, "parámetro 'dns' requerido", http.StatusBadRequest)
			return
		}
		msgBuf, err = base64.RawURLEncoding.DecodeString(b64)
		if err != nil {
			http.Error(w, "base64 inválido", http.StatusBadRequest)
			return
		}

	case http.MethodPost:
		// POST con Content-Type: application/dns-message
		if !strings.Contains(r.Header.Get("Content-Type"), "application/dns-message") {
			http.Error(w, "Content-Type debe ser application/dns-message", http.StatusUnsupportedMediaType)
			return
		}
		msgBuf, err = io.ReadAll(io.LimitReader(r.Body, 65535))
		if err != nil {
			http.Error(w, "error leyendo body", http.StatusBadRequest)
			return
		}

	default:
		http.Error(w, "método no permitido", http.StatusMethodNotAllowed)
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(msgBuf); err != nil {
		http.Error(w, "mensaje DNS inválido", http.StatusBadRequest)
		return
	}

	dohW := &dohResponseWriter{
		responseWriter: w,
		remoteAddr:     remoteAddrFromRequest(r),
	}

	s.handler.ServeDNS(dohW, req)
}

func (s *Server) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if s.https != nil {
		s.https.Shutdown(ctx)
	}
	if s.plain != nil {
		s.plain.Shutdown(ctx)
	}
}

// dohResponseWriter implementa dns.ResponseWriter sobre http.ResponseWriter
type dohResponseWriter struct {
	responseWriter http.ResponseWriter
	remoteAddr     net.Addr
}

func (w *dohResponseWriter) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (w *dohResponseWriter) RemoteAddr() net.Addr { return w.remoteAddr }
func (w *dohResponseWriter) Close() error         { return nil }
func (w *dohResponseWriter) TsigStatus() error    { return nil }
func (w *dohResponseWriter) TsigTimersOnly(bool)  {}
func (w *dohResponseWriter) Hijack()              {}

func (w *dohResponseWriter) WriteMsg(m *dns.Msg) error {
	data, err := m.Pack()
	if err != nil {
		return err
	}
	return w.Write(data)
}

func (w *dohResponseWriter) Write(data []byte) error {
	w.responseWriter.Header().Set("Content-Type", "application/dns-message")
	w.responseWriter.Header().Set("Cache-Control", "no-store")
	_, err := w.responseWriter.Write(data)
	return err
}

func remoteAddrFromRequest(r *http.Request) net.Addr {
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.RemoteAddr
	}
	host, _, _ := net.SplitHostPort(ip)
	if host == "" {
		host = ip
	}
	return &net.TCPAddr{IP: net.ParseIP(host)}
}
