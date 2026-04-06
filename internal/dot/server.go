// Package dot implementa un servidor DNS over TLS (RFC 7858).
// Los clientes se conectan por TCP/TLS y envían mensajes DNS con prefijo
// de 2 bytes de longitud, igual que DNS sobre TCP normal.
package dot

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/miekg/dns"
)

// Config parámetros del servidor DoT
type Config struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`   // default: "0.0.0.0:853"
	Timeout string `yaml:"timeout"`  // default: "10s"
}

// Server es el servidor DNS over TLS
type Server struct {
	cfg       Config
	tlsCfg    *tls.Config
	handler   dns.Handler
	listener  net.Listener
	done      chan struct{}
}

func New(cfg Config, tlsCfg *tls.Config, handler dns.Handler) *Server {
	if cfg.Listen == "" {
		cfg.Listen = "0.0.0.0:853"
	}
	return &Server{
		cfg:     cfg,
		tlsCfg:  tlsCfg,
		handler: handler,
		done:    make(chan struct{}),
	}
}

func (s *Server) ListenAndServe() error {
	ln, err := tls.Listen("tcp", s.cfg.Listen, s.tlsCfg)
	if err != nil {
		return err
	}
	s.listener = ln

	for {
		select {
		case <-s.done:
			return nil
		default:
		}
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return nil
			default:
				continue
			}
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	for {
		conn.SetDeadline(time.Now().Add(10 * time.Second))

		// Leer prefijo de 2 bytes con la longitud del mensaje
		var msgLen uint16
		if err := binary.Read(conn, binary.BigEndian, &msgLen); err != nil {
			return
		}

		buf := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}

		req := new(dns.Msg)
		if err := req.Unpack(buf); err != nil {
			return
		}

		// Usar el writer TLS para responder
		w := &dotResponseWriter{conn: conn, remoteAddr: conn.RemoteAddr()}
		s.handler.ServeDNS(w, req)
	}
}

func (s *Server) Shutdown() {
	close(s.done)
	if s.listener != nil {
		s.listener.Close()
	}
}

// dotResponseWriter implementa dns.ResponseWriter sobre una conexión TLS
type dotResponseWriter struct {
	conn       net.Conn
	remoteAddr net.Addr
	localAddr  net.Addr
}

func (w *dotResponseWriter) LocalAddr() net.Addr         { return w.conn.LocalAddr() }
func (w *dotResponseWriter) RemoteAddr() net.Addr        { return w.remoteAddr }
func (w *dotResponseWriter) Close() error                { return w.conn.Close() }
func (w *dotResponseWriter) TsigStatus() error           { return nil }
func (w *dotResponseWriter) TsigTimersOnly(bool)         {}
func (w *dotResponseWriter) Hijack()                     {}

func (w *dotResponseWriter) WriteMsg(m *dns.Msg) error {
	data, err := m.Pack()
	if err != nil {
		return err
	}
	return w.Write(data)
}

func (w *dotResponseWriter) Write(data []byte) error {
	// DNS/TCP: prefijo de 2 bytes con la longitud
	buf := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(data)))
	copy(buf[2:], data)
	_, err := w.conn.Write(buf)
	return err
}
