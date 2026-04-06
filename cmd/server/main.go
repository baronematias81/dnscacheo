package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"gopkg.in/yaml.v3"

	"github.com/baronematias81/dnscacheo/internal/api"
	"github.com/baronematias81/dnscacheo/internal/cache"
	"github.com/baronematias81/dnscacheo/internal/db"
	"github.com/baronematias81/dnscacheo/internal/doh"
	"github.com/baronematias81/dnscacheo/internal/dot"
	"github.com/baronematias81/dnscacheo/internal/filter"
	"github.com/baronematias81/dnscacheo/internal/logger"
	"github.com/baronematias81/dnscacheo/internal/metrics"
	"github.com/baronematias81/dnscacheo/internal/policy"
	"github.com/baronematias81/dnscacheo/internal/querylog"
	"github.com/baronematias81/dnscacheo/internal/ratelimit"
	"github.com/baronematias81/dnscacheo/internal/resolver"
	"github.com/baronematias81/dnscacheo/internal/tlsutil"
	"github.com/baronematias81/dnscacheo/internal/tunnel"
)

// Config estructura completa del archivo config.yaml
type Config struct {
	Server struct {
		ListenUDP4  string   `yaml:"listen_udp4"`
		ListenTCP4  string   `yaml:"listen_tcp4"`
		IPv6Enabled bool     `yaml:"ipv6_enabled"`
		ListenUDP6  string   `yaml:"listen_udp6"`
		ListenTCP6  string   `yaml:"listen_tcp6"`
		Upstreams4  []string `yaml:"upstreams4"`
		Upstreams6  []string `yaml:"upstreams6"`
		Timeout     string   `yaml:"timeout"`
	} `yaml:"server"`

	Cache struct {
		RedisURL   string `yaml:"redis_url"`
		DefaultTTL int    `yaml:"default_ttl"`
	} `yaml:"cache"`

	Database struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		Name     string `yaml:"name"`
		User     string `yaml:"user"`
		Password string `yaml:"password"`
	} `yaml:"database"`

	TLS tlsutil.Config `yaml:"tls"`
	DoT dot.Config     `yaml:"dot"`
	DoH doh.Config     `yaml:"doh"`

	Filter struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"filter"`

	ZeroTrust struct {
		Enabled          bool   `yaml:"enabled"`
		RequireEncrypted bool   `yaml:"require_encrypted"`
		DefaultPolicy    string `yaml:"default_policy"`
	} `yaml:"zero_trust"`

	RateLimit ratelimit.Config `yaml:"rate_limit"`

	Metrics struct {
		Enabled bool   `yaml:"enabled"`
		Listen  string `yaml:"listen"`
	} `yaml:"metrics"`

	TunnelDetection struct {
		Enabled          bool    `yaml:"enabled"`
		EntropyMin       float64 `yaml:"entropy_min"`
		LabelLenMin      int     `yaml:"label_len_min"`
		UniqueSubsWindow int     `yaml:"unique_subs_window"`
		UniqueSubsMin    int     `yaml:"unique_subs_min"`
		QueryRateWindow  int     `yaml:"query_rate_window"`
		QueryRateMin     int     `yaml:"query_rate_min"`
	} `yaml:"tunnel_detection"`

	Logging struct {
		Level    string `yaml:"level"`
		QueryLog bool   `yaml:"query_log"`
	} `yaml:"logging"`
}

func main() {
	configPath := flag.String("config", "config/config.yaml", "Path al archivo de configuración")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Error cargando config: %v", err)
	}

	appLog := logger.New(cfg.Logging.Level)
	appLog.Info("Iniciando dnscacheo — DNS Cache Server para Grupo Barone SRL")

	// ── Base de datos ──────────────────────────────────────
	postgres, err := db.Connect(db.Config{
		Host:     cfg.Database.Host,
		Port:     cfg.Database.Port,
		Name:     cfg.Database.Name,
		User:     cfg.Database.User,
		Password: cfg.Database.Password,
	})
	if err != nil {
		appLog.Error("No se pudo conectar a PostgreSQL", "error", err)
		os.Exit(1)
	}
	defer postgres.Close()
	appLog.Info("Conectado a PostgreSQL")

	// ── Componentes core ───────────────────────────────────
	redisCache  := cache.NewRedisCache(cfg.Cache.RedisURL)
	queryFilter := filter.New(cfg.Filter.Enabled)
	policyEng   := policy.New(cfg.ZeroTrust.DefaultPolicy)
	qlog        := querylog.New(postgres)
	defer qlog.Close()

	// ── Rate limiter ────────────────────────────────────────
	rlCfg := cfg.RateLimit
	if rlCfg.GlobalRate == 0 {
		rlCfg = ratelimit.DefaultConfig()
	}
	rateLimiter := ratelimit.New(rlCfg)
	appLog.Info("Rate limiter iniciado", "rate", rlCfg.GlobalRate, "burst", rlCfg.GlobalBurst)

	// ── Métricas Prometheus ─────────────────────────────────
	if cfg.Metrics.Enabled {
		addr := cfg.Metrics.Listen
		if addr == "" {
			addr = "0.0.0.0:9090"
		}
		go metrics.StartServer(addr)
		appLog.Info("Métricas Prometheus en", "addr", addr+"/metrics")
	}

	// ── Detección de tunneling ─────────────────────────────
	tunnelStore := tunnel.NewStore(postgres)
	defer tunnelStore.Close()

	th := tunnel.DefaultThresholds()
	if t := cfg.TunnelDetection; t.Enabled {
		if t.EntropyMin > 0      { th.EntropyMin       = t.EntropyMin }
		if t.LabelLenMin > 0     { th.LabelLenMin       = t.LabelLenMin }
		if t.UniqueSubsWindow > 0 { th.UniqueSubsWindow = t.UniqueSubsWindow }
		if t.UniqueSubsMin > 0   { th.UniqueSubsMin     = t.UniqueSubsMin }
		if t.QueryRateWindow > 0 { th.QueryRateWindow   = t.QueryRateWindow }
		if t.QueryRateMin > 0    { th.QueryRateMin       = t.QueryRateMin }
	}

	tunnelDetector := tunnel.New(th, func(a tunnel.Alert) {
		tunnelStore.Save(a)
		if a.Severity == tunnel.SeverityHigh || a.Severity == tunnel.SeverityCritical {
			appLog.Warn("DNS Tunnel detectado",
				"client", a.ClientIP, "domain", a.Domain,
				"type", a.AlertType, "score", a.Score, "severity", a.Severity,
			)
		}
	})

	// ── Resolver DNS — IPv4 + IPv6 ─────────────────────────
	resCfg := resolver.Config{
		ListenUDP4:  cfg.Server.ListenUDP4,
		ListenTCP4:  cfg.Server.ListenTCP4,
		IPv6Enabled: cfg.Server.IPv6Enabled,
		ListenUDP6:  cfg.Server.ListenUDP6,
		ListenTCP6:  cfg.Server.ListenTCP6,
		Upstreams4:  cfg.Server.Upstreams4,
		Upstreams6:  cfg.Server.Upstreams6,
		Timeout:     cfg.Server.Timeout,
	}
	if len(resCfg.Upstreams4) == 0 {
		resCfg.Upstreams4 = resolver.DefaultConfig().Upstreams4
	}
	if len(resCfg.Upstreams6) == 0 {
		resCfg.Upstreams6 = resolver.DefaultConfig().Upstreams6
	}

	dnsResolver := resolver.New(resCfg, redisCache, queryFilter, policyEng, qlog, tunnelDetector, rateLimiter)

	go func() {
		proto := "IPv4"
		if cfg.Server.IPv6Enabled {
			proto = "IPv4 + IPv6"
		}
		appLog.Info("DNS escuchando", "proto", proto,
			"udp4", resCfg.ListenUDP4, "tcp4", resCfg.ListenTCP4,
			"udp6", resCfg.ListenUDP6, "tcp6", resCfg.ListenTCP6)
		if err := dnsResolver.ListenAndServe(); err != nil {
			appLog.Error("Error en servidor DNS", "error", err)
		}
	}()

	// ── TLS + DoT + DoH ────────────────────────────────────
	var dotServer *dot.Server
	var dohServer *doh.Server

	if cfg.TLS.Enabled && (cfg.DoT.Enabled || cfg.DoH.Enabled) {
		tlsCfg, err := tlsutil.Load(cfg.TLS)
		if err != nil {
			appLog.Error("Error cargando TLS", "error", err)
			os.Exit(1)
		}
		appLog.Info("TLS configurado correctamente")

		if cfg.DoT.Enabled {
			dotServer = dot.New(cfg.DoT, tlsCfg, dnsResolver.Handler())
			go func() {
				appLog.Info("DoT escuchando", "addr", cfg.DoT.Listen)
				if cfg.DoT.IPv6Enabled {
					appLog.Info("DoT IPv6 escuchando", "addr", cfg.DoT.ListenIPv6)
				}
				if err := dotServer.ListenAndServe(); err != nil {
					appLog.Error("Error en DoT", "error", err)
				}
			}()
		}

		if cfg.DoH.Enabled {
			dohServer = doh.New(cfg.DoH, tlsCfg, dnsResolver.Handler())
			go func() {
				appLog.Info("DoH escuchando", "addr", cfg.DoH.Listen, "path", cfg.DoH.Path)
				if cfg.DoH.IPv6Enabled {
					appLog.Info("DoH IPv6 escuchando", "addr", cfg.DoH.ListenIPv6)
				}
				if err := dohServer.ListenAndServe(); err != nil {
					appLog.Error("Error en DoH", "error", err)
				}
			}()
		}
	} else if (cfg.DoT.Enabled || cfg.DoH.Enabled) && !cfg.TLS.Enabled {
		appLog.Warn("DoT/DoH habilitados pero tls.enabled=false — no se inician")
	}

	// ── API REST ───────────────────────────────────────────
	adminAPI := api.New(redisCache, policyEng, qlog, tunnelStore, postgres, appLog)
	adminAPI.SetEncryptionStatus(cfg.DoT.Enabled && cfg.TLS.Enabled, cfg.DoH.Enabled && cfg.TLS.Enabled)
	go func() {
		appLog.Info("API de administración escuchando", "addr", ":8080")
		adminAPI.Run()
	}()

	appLog.Info("dnscacheo listo", "ipv6", cfg.Server.IPv6Enabled)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	appLog.Info("Apagando dnscacheo...")
	dnsResolver.Shutdown()
	if dotServer != nil { dotServer.Shutdown() }
	if dohServer != nil { dohServer.Shutdown() }
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
