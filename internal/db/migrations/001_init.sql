-- Tabla principal de logs de consultas DNS
CREATE TABLE IF NOT EXISTS dns_query_logs (
    id            BIGSERIAL PRIMARY KEY,
    timestamp     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    client_ip     INET NOT NULL,
    domain        TEXT NOT NULL,
    query_type    VARCHAR(10) NOT NULL,   -- A, AAAA, MX, CNAME, etc.
    response_code VARCHAR(20) NOT NULL,   -- NOERROR, NXDOMAIN, REFUSED, SERVFAIL
    latency_ms    INTEGER NOT NULL,       -- tiempo de respuesta en ms
    cache_hit     BOOLEAN NOT NULL DEFAULT FALSE,
    blocked       BOOLEAN NOT NULL DEFAULT FALSE,
    block_reason  VARCHAR(50),            -- malware, ads, policy, ratelimit
    upstream      VARCHAR(50),            -- upstream usado (null si fue caché)
    answers       INTEGER DEFAULT 0       -- cantidad de respuestas
);

-- Índices para consultas frecuentes
CREATE INDEX idx_dns_logs_timestamp   ON dns_query_logs (timestamp DESC);
CREATE INDEX idx_dns_logs_client_ip   ON dns_query_logs (client_ip);
CREATE INDEX idx_dns_logs_domain      ON dns_query_logs (domain);
CREATE INDEX idx_dns_logs_blocked     ON dns_query_logs (blocked) WHERE blocked = TRUE;
CREATE INDEX idx_dns_logs_cache_hit   ON dns_query_logs (cache_hit);

-- Tabla de estadísticas diarias por cliente (agregado para reportes rápidos)
CREATE TABLE IF NOT EXISTS dns_client_stats (
    id              BIGSERIAL PRIMARY KEY,
    date            DATE NOT NULL,
    client_ip       INET NOT NULL,
    total_queries   BIGINT NOT NULL DEFAULT 0,
    cache_hits      BIGINT NOT NULL DEFAULT 0,
    blocked_queries BIGINT NOT NULL DEFAULT 0,
    unique_domains  BIGINT NOT NULL DEFAULT 0,
    avg_latency_ms  NUMERIC(8,2),
    UNIQUE (date, client_ip)
);

CREATE INDEX idx_client_stats_date      ON dns_client_stats (date DESC);
CREATE INDEX idx_client_stats_client_ip ON dns_client_stats (client_ip);

-- Tabla de dominios más consultados (top dominios)
CREATE TABLE IF NOT EXISTS dns_top_domains (
    id          BIGSERIAL PRIMARY KEY,
    date        DATE NOT NULL,
    domain      TEXT NOT NULL,
    query_count BIGINT NOT NULL DEFAULT 0,
    UNIQUE (date, domain)
);

CREATE INDEX idx_top_domains_date  ON dns_top_domains (date DESC);
CREATE INDEX idx_top_domains_count ON dns_top_domains (query_count DESC);

-- Vista: resumen de actividad por cliente (últimas 24h)
CREATE OR REPLACE VIEW v_client_activity_24h AS
SELECT
    client_ip,
    COUNT(*) AS total_queries,
    SUM(CASE WHEN cache_hit  THEN 1 ELSE 0 END) AS cache_hits,
    SUM(CASE WHEN blocked    THEN 1 ELSE 0 END) AS blocked,
    ROUND(AVG(latency_ms), 2)                   AS avg_latency_ms,
    COUNT(DISTINCT domain)                       AS unique_domains,
    MAX(timestamp)                               AS last_query
FROM dns_query_logs
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY client_ip
ORDER BY total_queries DESC;

-- Vista: dominios bloqueados más intentados
CREATE OR REPLACE VIEW v_top_blocked_domains AS
SELECT
    domain,
    block_reason,
    COUNT(*) AS attempts,
    COUNT(DISTINCT client_ip) AS unique_clients
FROM dns_query_logs
WHERE blocked = TRUE
  AND timestamp > NOW() - INTERVAL '24 hours'
GROUP BY domain, block_reason
ORDER BY attempts DESC
LIMIT 100;

-- Función para agregar stats diarias (ejecutar con cron)
CREATE OR REPLACE FUNCTION aggregate_daily_stats(target_date DATE DEFAULT CURRENT_DATE - 1)
RETURNS VOID AS $$
BEGIN
    INSERT INTO dns_client_stats (date, client_ip, total_queries, cache_hits, blocked_queries, unique_domains, avg_latency_ms)
    SELECT
        target_date,
        client_ip,
        COUNT(*),
        SUM(CASE WHEN cache_hit THEN 1 ELSE 0 END),
        SUM(CASE WHEN blocked   THEN 1 ELSE 0 END),
        COUNT(DISTINCT domain),
        ROUND(AVG(latency_ms), 2)
    FROM dns_query_logs
    WHERE timestamp::DATE = target_date
    GROUP BY client_ip
    ON CONFLICT (date, client_ip) DO UPDATE SET
        total_queries   = EXCLUDED.total_queries,
        cache_hits      = EXCLUDED.cache_hits,
        blocked_queries = EXCLUDED.blocked_queries,
        unique_domains  = EXCLUDED.unique_domains,
        avg_latency_ms  = EXCLUDED.avg_latency_ms;

    INSERT INTO dns_top_domains (date, domain, query_count)
    SELECT target_date, domain, COUNT(*)
    FROM dns_query_logs
    WHERE timestamp::DATE = target_date
    GROUP BY domain
    ON CONFLICT (date, domain) DO UPDATE SET
        query_count = EXCLUDED.query_count;
END;
$$ LANGUAGE plpgsql;
