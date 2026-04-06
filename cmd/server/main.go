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
	"github.com/baronematias81/dnscacheo/internal/filter"
	"github.com/baronematias81/dnscacheo/internal/logger"
	"github.com/baronematias81/dnscacheo/internal/policy"
	"github.com/baronematias81/dnscacheo/internal/querylog"
	"github.com/baronematias81/dnscacheo/internal/resolver"
)

type Config struct {
	Server struct {
		Listen    string `yaml:"listen"`
		ListenDoH string `yaml:"listen_doh"`
		ListenDoT string `yaml:"listen_dot"`
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
	Filter struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"filter"`
	ZeroTrust struct {
		Enabled       bool   `yaml:"enabled"`
		DefaultPolicy string `yaml:"default_policy"`
	} `yaml:"zero_trust"`
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
	appLog.Info("Iniciando dnscacheo - DNS Cache Server para Grupo Barone SRL")

	// Conectar a PostgreSQL
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

	// Inicializar componentes
	redisCache  := cache.NewRedisCache(cfg.Cache.RedisURL)
	queryFilter := filter.New(cfg.Filter.Enabled)
	policyEng   := policy.New(cfg.ZeroTrust.DefaultPolicy)
	qlog        := querylog.New(postgres)
	defer qlog.Close()

	dnsResolver := resolver.New(redisCache, queryFilter, policyEng, qlog)
	adminAPI    := api.New(redisCache, policyEng, qlog, postgres, appLog)

	// Iniciar servidor DNS
	go func() {
		appLog.Info("Escuchando DNS en :53 (UDP)")
		if err := dnsResolver.ListenAndServe(); err != nil {
			appLog.Error("Error en servidor DNS", "error", err)
		}
	}()

	// Iniciar API REST de administración
	go func() {
		appLog.Info("API de administración en :8080")
		adminAPI.Run()
	}()

	appLog.Info("dnscacheo iniciado correctamente")

	// Esperar señal de apagado
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	appLog.Info("Apagando dnscacheo...")
	dnsResolver.Shutdown()
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
