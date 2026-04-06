// Package tlsutil provee utilidades para cargar o generar certificados TLS.
// Si cert_file y key_file existen los usa; si no y auto_generate=true genera
// un certificado autofirmado RSA-2048 válido por 10 años.
package tlsutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// Config parámetros TLS del servidor
type Config struct {
	Enabled      bool     `yaml:"enabled"`
	CertFile     string   `yaml:"cert_file"`
	KeyFile      string   `yaml:"key_file"`
	AutoGenerate bool     `yaml:"auto_generate"`
	SANs         []string `yaml:"sans"` // IPs y hostnames adicionales en el cert
	MinVersion   string   `yaml:"min_version"` // "1.2" | "1.3"
}

// Load devuelve un *tls.Config listo para usar.
// Si los archivos no existen y AutoGenerate=true los crea en disco.
func Load(cfg Config) (*tls.Config, error) {
	certFile := cfg.CertFile
	keyFile  := cfg.KeyFile

	if certFile == "" {
		certFile = "certs/server.crt"
	}
	if keyFile == "" {
		keyFile = "certs/server.key"
	}

	// Si no existen y está habilitado auto_generate → crear
	if (!fileExists(certFile) || !fileExists(keyFile)) && cfg.AutoGenerate {
		if err := generateSelfSigned(certFile, keyFile, cfg.SANs); err != nil {
			return nil, fmt.Errorf("generando cert autofirmado: %w", err)
		}
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("cargando cert TLS: %w", err)
	}

	minVersion := uint16(tls.VersionTLS12)
	if cfg.MinVersion == "1.3" {
		minVersion = tls.VersionTLS13
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVersion,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}, nil
}

// generateSelfSigned crea un certificado autofirmado RSA-2048.
func generateSelfSigned(certFile, keyFile string, sans []string) error {
	// Crear directorio si no existe
	if err := os.MkdirAll(dirOf(certFile), 0700); err != nil {
		return err
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Grupo Barone SRL"},
			CommonName:   "dnscacheo",
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Agregar localhost + SANs configurados
	defaultSANs := append([]string{"localhost", "127.0.0.1"}, sans...)
	for _, san := range defaultSANs {
		if ip := net.ParseIP(san); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, san)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	// Escribir cert
	cf, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer cf.Close()
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Escribir key
	kf, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer kf.Close()
	pem.Encode(kf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return "."
}
