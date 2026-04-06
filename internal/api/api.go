package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/baronematias81/dnscacheo/internal/cache"
	"github.com/baronematias81/dnscacheo/internal/policy"
)

type API struct {
	cache  *cache.RedisCache
	policy *policy.Engine
	router *gin.Engine
}

func New(cfg interface{}, c *cache.RedisCache, p *policy.Engine, log interface{}) *API {
	gin.SetMode(gin.ReleaseMode)
	a := &API{
		cache:  c,
		policy: p,
		router: gin.New(),
	}
	a.setupRoutes()
	return a
}

func (a *API) setupRoutes() {
	v1 := a.router.Group("/api/v1")

	// Caché
	v1.DELETE("/cache", a.flushCache)
	v1.DELETE("/cache/:domain", a.deleteCacheEntry)
	v1.GET("/cache/stats", a.cacheStats)

	// Políticas Zero Trust
	v1.GET("/policies", a.listPolicies)
	v1.POST("/policies", a.createPolicy)
	v1.DELETE("/policies/:ip", a.deletePolicy)

	// Estado general
	v1.GET("/health", a.health)
	v1.GET("/stats", a.stats)
}

func (a *API) Run() {
	a.router.Run(":8080")
}

func (a *API) flushCache(c *gin.Context) {
	a.cache.Flush()
	c.JSON(http.StatusOK, gin.H{"message": "caché limpiado"})
}

func (a *API) deleteCacheEntry(c *gin.Context) {
	domain := c.Param("domain")
	a.cache.Delete(domain, 1) // tipo A
	c.JSON(http.StatusOK, gin.H{"message": "entrada eliminada", "domain": domain})
}

func (a *API) cacheStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (a *API) listPolicies(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"policies": []string{}})
}

func (a *API) createPolicy(c *gin.Context) {
	var p policy.ClientPolicy
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	a.policy.SetPolicy(p.ClientIP, &p)
	c.JSON(http.StatusCreated, gin.H{"message": "política creada"})
}

func (a *API) deletePolicy(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "política eliminada"})
}

func (a *API) health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "dnscacheo"})
}

func (a *API) stats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"service": "dnscacheo",
		"version": "1.0.0",
		"empresa": "Grupo Barone SRL",
	})
}
