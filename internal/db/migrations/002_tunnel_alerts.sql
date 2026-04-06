-- Tabla de alertas de DNS tunneling
CREATE TABLE IF NOT EXISTS dns_tunnel_alerts (
    id            BIGSERIAL PRIMARY KEY,
    timestamp     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    client_ip     INET NOT NULL,
    domain        TEXT NOT NULL,
    parent_domain TEXT NOT NULL,
    query_type    VARCHAR(10) NOT NULL,
    alert_type    VARCHAR(50) NOT NULL,   -- high_entropy | long_label | unique_subdomains | query_rate | suspicious_type
    severity      VARCHAR(10) NOT NULL,   -- low | medium | high | critical
    score         NUMERIC(5,2) NOT NULL,  -- score combinado 0-100
    details       JSONB,                  -- detalles específicos del algoritmo
    resolved      BOOLEAN NOT NULL DEFAULT FALSE,
    resolved_at   TIMESTAMPTZ,
    notes         TEXT
);

CREATE INDEX idx_tunnel_timestamp  ON dns_tunnel_alerts (timestamp DESC);
CREATE INDEX idx_tunnel_client_ip  ON dns_tunnel_alerts (client_ip);
CREATE INDEX idx_tunnel_severity   ON dns_tunnel_alerts (severity);
CREATE INDEX idx_tunnel_resolved   ON dns_tunnel_alerts (resolved) WHERE resolved = FALSE;

-- Vista: alertas activas (sin resolver, últimas 24h)
CREATE OR REPLACE VIEW v_active_tunnel_alerts AS
SELECT
    id, timestamp, client_ip, domain, alert_type, severity, score, details
FROM dns_tunnel_alerts
WHERE resolved = FALSE
  AND timestamp > NOW() - INTERVAL '24 hours'
ORDER BY score DESC, timestamp DESC;

-- Vista: clientes con más alertas
CREATE OR REPLACE VIEW v_tunnel_clients AS
SELECT
    client_ip,
    COUNT(*) AS total_alerts,
    SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical,
    SUM(CASE WHEN severity = 'high'     THEN 1 ELSE 0 END) AS high,
    MAX(score) AS max_score,
    MAX(timestamp) AS last_alert
FROM dns_tunnel_alerts
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY client_ip
ORDER BY total_alerts DESC;
