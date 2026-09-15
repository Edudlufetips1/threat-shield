package db

import (
	"context"

	"github.com/Edudlufetips1/threat-shield/internal/model"
	"github.com/jackc/pgx/v5"
)

// RecordHistory persists one observed snapshot after the history table exists.
func RecordHistory(ctx context.Context, conn *pgx.Conn, vuln model.Vulnerability) error {
	_, err := conn.Exec(ctx,
		`INSERT INTO vulnerability_history (
			cve_id,
			title,
			description,
			source,
			date_added,
			ransomware_use,
			due_date,
			threat_index
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		vuln.ID,
		vuln.Title,
		vuln.Description,
		vuln.Source,
		vuln.Date,
		vuln.RansomwareUse,
		vuln.DueDate,
		vuln.ThreatIndex,
	)
	return err
}
