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
	"github.com/baronematias81/dnscacheo/internal/policy"
	"github.com/baronematias81/dnscacheo/internal/querylog"
	"github.com/baronematias81/dnscacheo/internal/resolver"
	"github.com/baronematias81/dnscacheo/internal/tlsutil"
	"github.com/baronematias81/dnscacheo/internal/tunnel"
)

// Config estructura completa del archivo config.yaml
type Config struct {
	Server struct {
		Listen  string `yaml:"listen"`
		Workers int    `yaml:"workers"`
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
		Enabled           bool   `yaml:"enabled"`
		RequireEncrypted  bool   `yaml:"require_encrypted"`
		DefaultPolicy     string `yaml:"default_policy"`
	} `yaml:"zero_trust"`

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

	// ── Detección de tunneling ─────────────────────────────
	tunnelStore    := tunnel.NewStore(postgres)
	defer tunnelStore.Close()

	tunnelThresholds := tunnel.DefaultThresholds()
	if cfg.TunnelDetection.Enabled {
		if cfg.TunnelDetection.EntropyMin > 0 {
			tunnelThresholds.EntropyMin = cfg.TunnelDetection.EntropyMin
		}
		if cfg.TunnelDetection.LabelLenMin > 0 {
			tunnelThresholds.LabelLenMin = cfg.TunnelDetection.LabelLenMin
		}
		if cfg.TunnelDetection.UniqueSubsWindow > 0 {
			tunnelThresholds.UniqueSubsWindow = cfg.TunnelDetection.UniqueSubsWindow
		}
		if cfg.TunnelDetection.UniqueSubsMin > 0 {
			tunnelThresholds.UniqueSubsMin = cfg.TunnelDetection.UniqueSubsMin
		}
		if cfg.TunnelDetection.QueryRateWindow > 0 {
			tunnelThresholds.QueryRateWindow = cfg.TunnelDetection.QueryRateWindow
		}
		if cfg.TunnelDetection.QueryRateMin > 0 {
			tunnelThresholds.QueryRateMin = cfg.TunnelDetection.QueryRateMin
		}
	}

	tunnelDetector := tunnel.New(tunnelThresholds, func(a tunnel.Alert) {
		tunnelStore.Save(a)
		if a.Severity == tunnel.SeverityHigh || a.Severity == tunnel.SeverityCritical {
			appLog.Warn("DNS Tunnel detectado",
				"client", a.ClientIP,
				"domain", a.Domain,
				"type", a.AlertType,
				"score", a.Score,
				"severity", a.Severity,
			)
		}
	})

	// ── Resolver DNS core ──────────────────────────────────
	dnsResolver := resolver.New(redisCache, queryFilter, policyEng, qlog, tunnelDetector)

	// ── Servidor DNS UDP/TCP (puerto 53) ───────────────────
	go func() {
		appLog.Info("DNS UDP/TCP escuchando", "addr", cfg.Server.Listen)
		if err := dnsResolver.ListenAndServe(); err != nil {
			appLog.Error("Error en servidor DNS", "error", err)
		}
	}()

	// ── TLS (compartido por DoT y DoH) ─────────────────────
	var dotServer *dot.Server
	var dohServer *doh.Server

	if cfg.TLS.Enabled && (cfg.DoT.Enabled || cfg.DoH.Enabled) {
		tlsCfg, err := tlsutil.Load(cfg.TLS)
		if err != nil {
			appLog.Error("Error cargando TLS", "error", err)
			os.Exit(1)
		}
		appLog.Info("TLS configurado correctamente")

		// ── DNS over TLS (puerto 853) ──────────────────────
		if cfg.DoT.Enabled {
			dotServer = dot.New(cfg.DoT, tlsCfg, dnsResolver.Handler())
			go func() {
				appLog.Info("DoT escuchando", "addr", cfg.DoT.Listen)
				if err := dotServer.ListenAndServe(); err != nil {
					appLog.Error("Error en servidor DoT", "error", err)
				}
			}()
		}

		// ── DNS over HTTPS (puerto 443) ────────────────────
		if cfg.DoH.Enabled {
			dohServer = doh.New(cfg.DoH, tlsCfg, dnsResolver.Handler())
			go func() {
				appLog.Info("DoH escuchando", "addr", cfg.DoH.Listen, "path", cfg.DoH.Path)
				if cfg.DoH.ListenPlain != "" {
					appLog.Info("DoH HTTP plano", "addr", cfg.DoH.ListenPlain)
				}
				if err := dohServer.ListenAndServe(); err != nil {
					appLog.Error("Error en servidor DoH", "error", err)
				}
			}()
		}
	} else if (cfg.DoT.Enabled || cfg.DoH.Enabled) && !cfg.TLS.Enabled {
		appLog.Warn("DoT/DoH habilitados pero tls.enabled=false — no se inician")
	}

	// ── API REST de administración (puerto 8080) ───────────
	adminAPI := api.New(redisCache, policyEng, qlog, tunnelStore, postgres, appLog)
	adminAPI.SetEncryptionStatus(cfg.DoT.Enabled && cfg.TLS.Enabled, cfg.DoH.Enabled && cfg.TLS.Enabled)
	go func() {
		appLog.Info("API de administración escuchando", "addr", ":8080")
		adminAPI.Run()
	}()

	appLog.Info("dnscacheo iniciado correctamente")

	// ── Esperar señal de apagado ───────────────────────────
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	appLog.Info("Apagando dnscacheo...")
	dnsResolver.Shutdown()
	if dotServer != nil {
		dotServer.Shutdown()
	}
	if dohServer != nil {
		dohServer.Shutdown()
	}
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
