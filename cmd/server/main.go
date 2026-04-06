package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/baronematias81/dnscacheo/internal/api"
	"github.com/baronematias81/dnscacheo/internal/cache"
	"github.com/baronematias81/dnscacheo/internal/filter"
	"github.com/baronematias81/dnscacheo/internal/logger"
	"github.com/baronematias81/dnscacheo/internal/policy"
	"github.com/baronematias81/dnscacheo/internal/resolver"
)

func main() {
	configPath := flag.String("config", "config/config.yaml", "Path to config file")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	log := logger.New(cfg.Logging)
	log.Info("Starting dnscacheo - DNS Cache Server para Grupo Barone SRL")

	redisCache := cache.NewRedisCache(cfg.Cache)
	queryFilter := filter.New(cfg.Filter)
	policyEngine := policy.New(cfg.ZeroTrust, cfg.Database)
	dnsResolver := resolver.New(cfg, redisCache, queryFilter, policyEngine, log)

	// Iniciar servidor DNS (UDP/TCP puerto 53)
	go dnsResolver.ListenAndServe()

	// Iniciar API REST de administración
	adminAPI := api.New(cfg, redisCache, policyEngine, log)
	go adminAPI.Run()

	log.Info("dnscacheo iniciado correctamente")

	// Esperar señal de apagado
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Info("Apagando dnscacheo...")
	dnsResolver.Shutdown()
}
