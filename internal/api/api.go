package api

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/baronematias81/dnscacheo/internal/cache"
	"github.com/baronematias81/dnscacheo/internal/logger"
	"github.com/baronematias81/dnscacheo/internal/policy"
	"github.com/baronematias81/dnscacheo/internal/querylog"
)

type API struct {
	cache  *cache.RedisCache
	policy *policy.Engine
	qlog   *querylog.QueryLogger
	db     *sql.DB
	log    *logger.Logger
	router *gin.Engine
}

func New(c *cache.RedisCache, p *policy.Engine, ql *querylog.QueryLogger, db *sql.DB, log *logger.Logger) *API {
	gin.SetMode(gin.ReleaseMode)
	a := &API{
		cache:  c,
		policy: p,
		qlog:   ql,
		db:     db,
		log:    log,
		router: gin.New(),
	}
	a.setupRoutes()
	return a
}

func (a *API) setupRoutes() {
	v1 := a.router.Group("/api/v1")

	// Caché
	v1.DELETE("/cache",          a.flushCache)
	v1.DELETE("/cache/:domain",  a.deleteCacheEntry)

	// Políticas Zero Trust
	v1.GET("/policies",          a.listPolicies)
	v1.POST("/policies",         a.createPolicy)
	v1.DELETE("/policies/:ip",   a.deletePolicy)

	// Logs y estadísticas
	v1.GET("/logs",              a.queryLogs)
	v1.GET("/stats/clients",     a.clientStats)
	v1.GET("/stats/top-domains", a.topDomains)
	v1.GET("/stats/blocked",     a.blockedDomains)

	// Estado
	v1.GET("/health",            a.health)
}

func (a *API) Run() {
	a.router.Run(":8080")
}

// --- Caché ---

func (a *API) flushCache(c *gin.Context) {
	a.cache.Flush()
	c.JSON(http.StatusOK, gin.H{"message": "caché limpiado"})
}

func (a *API) deleteCacheEntry(c *gin.Context) {
	domain := c.Param("domain")
	a.cache.Delete(domain, 1)
	c.JSON(http.StatusOK, gin.H{"message": "entrada eliminada", "domain": domain})
}

// --- Políticas ---

func (a *API) listPolicies(c *gin.Context) {
	c.JSON(http.StatusOK, a.policy.GetPolicies())
}

func (a *API) createPolicy(c *gin.Context) {
	var p policy.ClientPolicy
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	a.policy.SetPolicy(p.ClientIP, &p)
	c.JSON(http.StatusCreated, gin.H{"message": "política creada", "client_ip": p.ClientIP})
}

func (a *API) deletePolicy(c *gin.Context) {
	ip := c.Param("ip")
	a.policy.SetPolicy(ip, nil)
	c.JSON(http.StatusOK, gin.H{"message": "política eliminada", "client_ip": ip})
}

// --- Logs y estadísticas ---

func (a *API) queryLogs(c *gin.Context) {
	clientIP := c.Query("client_ip")
	domain   := c.Query("domain")
	limit    := c.DefaultQuery("limit", "100")

	query := `
		SELECT timestamp, client_ip, domain, query_type, response_code,
		       latency_ms, cache_hit, blocked, block_reason, upstream, answers
		FROM dns_query_logs
		WHERE ($1 = '' OR client_ip::text = $1)
		  AND ($2 = '' OR domain ILIKE $2)
		ORDER BY timestamp DESC
		LIMIT $3::int`

	rows, err := a.db.Query(query, clientIP, domain, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var logs []gin.H
	for rows.Next() {
		var (
			ts, ip, dom, qtype, rcode string
			latency, answers          int
			cacheHit, blocked         bool
			blockReason, upstream     sql.NullString
		)
		rows.Scan(&ts, &ip, &dom, &qtype, &rcode, &latency, &cacheHit, &blocked, &blockReason, &upstream, &answers)
		logs = append(logs, gin.H{
			"timestamp":    ts,
			"client_ip":    ip,
			"domain":       dom,
			"query_type":   qtype,
			"response":     rcode,
			"latency_ms":   latency,
			"cache_hit":    cacheHit,
			"blocked":      blocked,
			"block_reason": blockReason.String,
			"upstream":     upstream.String,
			"answers":      answers,
		})
	}
	c.JSON(http.StatusOK, gin.H{"logs": logs, "count": len(logs)})
}

func (a *API) clientStats(c *gin.Context) {
	rows, err := a.db.Query(`SELECT * FROM v_client_activity_24h LIMIT 100`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var stats []gin.H
	for rows.Next() {
		var ip, lastQuery string
		var total, hits, blocked, unique int
		var avgLatency float64
		rows.Scan(&ip, &total, &hits, &blocked, &avgLatency, &unique, &lastQuery)
		stats = append(stats, gin.H{
			"client_ip":      ip,
			"total_queries":  total,
			"cache_hits":     hits,
			"blocked":        blocked,
			"avg_latency_ms": avgLatency,
			"unique_domains": unique,
			"last_query":     lastQuery,
		})
	}
	c.JSON(http.StatusOK, gin.H{"clients": stats})
}

func (a *API) topDomains(c *gin.Context) {
	rows, err := a.db.Query(`
		SELECT domain, COUNT(*) AS queries, SUM(CASE WHEN cache_hit THEN 1 ELSE 0 END) AS cache_hits
		FROM dns_query_logs
		WHERE timestamp > NOW() - INTERVAL '24 hours'
		GROUP BY domain
		ORDER BY queries DESC
		LIMIT 50`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var domains []gin.H
	for rows.Next() {
		var dom string
		var queries, cacheHits int
		rows.Scan(&dom, &queries, &cacheHits)
		domains = append(domains, gin.H{"domain": dom, "queries": queries, "cache_hits": cacheHits})
	}
	c.JSON(http.StatusOK, gin.H{"top_domains": domains})
}

func (a *API) blockedDomains(c *gin.Context) {
	rows, err := a.db.Query(`SELECT * FROM v_top_blocked_domains`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var blocked []gin.H
	for rows.Next() {
		var dom, reason string
		var attempts, clients int
		rows.Scan(&dom, &reason, &attempts, &clients)
		blocked = append(blocked, gin.H{
			"domain":         dom,
			"reason":         reason,
			"attempts":       attempts,
			"unique_clients": clients,
		})
	}
	c.JSON(http.StatusOK, gin.H{"blocked_domains": blocked})
}

func (a *API) health(c *gin.Context) {
	dbOK := a.db.Ping() == nil
	c.JSON(http.StatusOK, gin.H{
		"status":   "ok",
		"service":  "dnscacheo",
		"empresa":  "Grupo Barone SRL",
		"postgres": dbOK,
	})
}
