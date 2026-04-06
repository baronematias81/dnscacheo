package tunnel

import (
	"database/sql"
	"encoding/json"
	"time"
)

// Store persiste y consulta alertas en PostgreSQL
type Store struct {
	db    *sql.DB
	queue chan Alert
	done  chan struct{}
}

func NewStore(db *sql.DB) *Store {
	s := &Store{
		db:    db,
		queue: make(chan Alert, 1000),
		done:  make(chan struct{}),
	}
	go s.worker()
	return s
}

func (s *Store) Save(a Alert) {
	select {
	case s.queue <- a:
	default:
		// buffer lleno, descartar para no frenar el detector
	}
}

func (s *Store) worker() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	batch := make([]Alert, 0, 50)

	for {
		select {
		case a := <-s.queue:
			batch = append(batch, a)
			if len(batch) >= 50 {
				s.flush(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				s.flush(batch)
				batch = batch[:0]
			}
		case <-s.done:
			for len(s.queue) > 0 {
				batch = append(batch, <-s.queue)
			}
			if len(batch) > 0 {
				s.flush(batch)
			}
			return
		}
	}
}

func (s *Store) flush(alerts []Alert) {
	tx, err := s.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO dns_tunnel_alerts
			(timestamp, client_ip, domain, parent_domain, query_type,
			 alert_type, severity, score, details)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`)
	if err != nil {
		return
	}
	defer stmt.Close()

	for _, a := range alerts {
		details, _ := json.Marshal(a.Details)
		stmt.Exec(
			a.Timestamp, a.ClientIP, a.Domain, a.ParentDomain,
			a.QueryType, string(a.AlertType), string(a.Severity),
			a.Score, details,
		)
	}
	tx.Commit()
}

func (s *Store) Close() { close(s.done) }

// AlertRow fila de alerta para la API
type AlertRow struct {
	ID           int64
	Timestamp    string
	ClientIP     string
	Domain       string
	ParentDomain string
	AlertType    string
	Severity     string
	Score        float64
	Details      string
	Resolved     bool
}

func (s *Store) ListActive(limit int) ([]AlertRow, error) {
	rows, err := s.db.Query(`
		SELECT id, timestamp, client_ip, domain, parent_domain,
		       alert_type, severity, score, details::text, resolved
		FROM dns_tunnel_alerts
		WHERE resolved = FALSE
		ORDER BY score DESC, timestamp DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []AlertRow
	for rows.Next() {
		var a AlertRow
		var details sql.NullString
		rows.Scan(&a.ID, &a.Timestamp, &a.ClientIP, &a.Domain,
			&a.ParentDomain, &a.AlertType, &a.Severity, &a.Score,
			&details, &a.Resolved)
		a.Details = details.String
		alerts = append(alerts, a)
	}
	return alerts, nil
}

func (s *Store) Resolve(id int64) error {
	_, err := s.db.Exec(
		`UPDATE dns_tunnel_alerts SET resolved=TRUE, resolved_at=NOW() WHERE id=$1`, id)
	return err
}

func (s *Store) ClientSummary() ([]map[string]interface{}, error) {
	rows, err := s.db.Query(`SELECT * FROM v_tunnel_clients LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var ip, lastAlert string
		var total, critical, high int
		var maxScore float64
		rows.Scan(&ip, &total, &critical, &high, &maxScore, &lastAlert)
		result = append(result, map[string]interface{}{
			"client_ip":     ip,
			"total_alerts":  total,
			"critical":      critical,
			"high":          high,
			"max_score":     maxScore,
			"last_alert":    lastAlert,
		})
	}
	return result, nil
}
