package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

type Vulnerability struct {
	ID            string  `json:"id"`
	Title         string  `json:"title"`
	Description   string  `json:"description"`
	Source        string  `json:"source"`
	Date          string  `json:"date"`
	RansomwareUse string  `json:"ransomware_use"`
	DueDate       string  `json:"due_date"`
	ThreatIndex   float64 `json:"threat_index"`
}

func ingestThreat(w http.ResponseWriter, r *http.Request, conn *pgx.Conn, scorer *ThreatScorer) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var vulns []Vulnerability
	err := json.NewDecoder(r.Body).Decode(&vulns)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	for _, vuln := range vulns {
		threatIndex := scorer.EvaluateVulnerability(vuln)
		_, err := conn.Exec(context.Background(),
			"INSERT INTO vulnerabilities (cve_id, title, description, source, date, ransomware_use, due_date, threat_index) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (cve_id) DO NOTHING",
			vuln.ID, vuln.Title, vuln.Description, vuln.Source, vuln.Date, vuln.RansomwareUse, vuln.DueDate, threatIndex)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte("Data received by Go engine"))
}

func getVulnerabilities(w http.ResponseWriter, r *http.Request, conn *pgx.Conn) {
	queryParams := r.URL.Query()
	baseQuery := "SELECT cve_id, title, description, source, date::text, ransomware_use, due_date, threat_index FROM vulnerabilities"
	var conditions []string
	var args []interface{}
	argCounter := 1

	minScore := queryParams.Get("min_score")
	if minScore != "" {
		threshold, err := strconv.ParseFloat(minScore, 64)
		if err != nil || threshold < 0 || threshold > 100 {
			http.Error(w, "Invalid min_score value (must be between 0 and 100)", http.StatusBadRequest)
			return
		}
		conditions = append(conditions, fmt.Sprintf("threat_index >= $%d", argCounter))
		args = append(args, threshold)
		argCounter++
	}

	if len(conditions) > 0 {
		baseQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	sortBy := queryParams.Get("sort")
	if sortBy == "" {
		sortBy = "threat_index"
	}
	switch sortBy {
	case "threat_index", "threatIndex", "":
		baseQuery += " ORDER BY threat_index DESC, cve_id DESC"
	case "cve_id", "cveId":
		baseQuery += " ORDER BY cve_id ASC"
	default:
		http.Error(w, "Invalid sort parameter", http.StatusBadRequest)
		return
	}

	limitStr := queryParams.Get("limit")
	if limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit < 0 {
			http.Error(w, "Invalid limit value (must be a non-negative integer)", http.StatusBadRequest)
			return
		}
		baseQuery += fmt.Sprintf(" LIMIT $%d", argCounter)
		args = append(args, limit)
	}
	rows, err := conn.Query(context.Background(), baseQuery, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	vulns := make([]Vulnerability, 0)
	for rows.Next() {
		var vuln Vulnerability
		err := rows.Scan(&vuln.ID, &vuln.Title, &vuln.Description, &vuln.Source, &vuln.Date, &vuln.RansomwareUse, &vuln.DueDate, &vuln.ThreatIndex)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		vulns = append(vulns, vuln)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vulns)
}
