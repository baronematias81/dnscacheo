package querylog

import (
	"database/sql"
	"time"
)

// Entry representa una consulta DNS a registrar
type Entry struct {
	Timestamp    time.Time
	ClientIP     string
	Domain       string
	QueryType    string
	ResponseCode string
	LatencyMs    int
	CacheHit     bool
	Blocked      bool
	BlockReason  string
	Upstream     string
	Answers      int
}

type QueryLogger struct {
	db    *sql.DB
	queue chan Entry
	done  chan struct{}
}

func New(db *sql.DB) *QueryLogger {
	ql := &QueryLogger{
		db:    db,
		queue: make(chan Entry, 10000), // buffer para no bloquear el resolver
		done:  make(chan struct{}),
	}
	go ql.worker()
	return ql
}

// Log encola una entrada de forma no bloqueante
func (ql *QueryLogger) Log(e Entry) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	select {
	case ql.queue <- e:
	default:
		// Si el buffer está lleno, descartamos para no frenar el DNS
	}
}

// worker consume el canal y escribe en lotes a PostgreSQL
func (ql *QueryLogger) worker() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	batch := make([]Entry, 0, 100)

	for {
		select {
		case e := <-ql.queue:
			batch = append(batch, e)
			if len(batch) >= 100 {
				ql.flush(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				ql.flush(batch)
				batch = batch[:0]
			}

		case <-ql.done:
			// Vaciar lo que queda antes de cerrar
			for len(ql.queue) > 0 {
				batch = append(batch, <-ql.queue)
			}
			if len(batch) > 0 {
				ql.flush(batch)
			}
			return
		}
	}
}

// flush inserta un lote en PostgreSQL usando COPY para máxima velocidad
func (ql *QueryLogger) flush(entries []Entry) {
	tx, err := ql.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO dns_query_logs
			(timestamp, client_ip, domain, query_type, response_code,
			 latency_ms, cache_hit, blocked, block_reason, upstream, answers)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	`)
	if err != nil {
		return
	}
	defer stmt.Close()

	for _, e := range entries {
		blockReason := sql.NullString{String: e.BlockReason, Valid: e.BlockReason != ""}
		upstream := sql.NullString{String: e.Upstream, Valid: e.Upstream != ""}

		_, err := stmt.Exec(
			e.Timestamp, e.ClientIP, e.Domain, e.QueryType,
			e.ResponseCode, e.LatencyMs, e.CacheHit, e.Blocked,
			blockReason, upstream, e.Answers,
		)
		if err != nil {
			continue
		}
	}

	tx.Commit()
}

func (ql *QueryLogger) Close() {
	close(ql.done)
}
