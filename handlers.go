package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
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

func queryVulnerabilities(conn *pgx.Conn, queryParams url.Values) ([]Vulnerability, error) {
	baseQuery := "SELECT cve_id, title, description, source, date::text, ransomware_use, due_date, threat_index FROM vulnerabilities"
	var conditions []string
	var args []interface{}
	argCounter := 1

	minScore := queryParams.Get("min_score")
	if minScore != "" {
		threshold, err := strconv.ParseFloat(minScore, 64)
		if err != nil || threshold < 0 || threshold > 100 {
			return nil, fmt.Errorf("invalid min_score value (must be between 0 and 100)")
		}
		conditions = append(conditions, fmt.Sprintf("threat_index >= $%d", argCounter))
		args = append(args, threshold)
		argCounter++
	}

	searchQuery := queryParams.Get("search")
	if searchQuery != "" {
		conditions = append(conditions, fmt.Sprintf("(cve_id ILIKE $%d OR title ILIKE $%d OR description ILIKE $%d)", argCounter, argCounter, argCounter))
		args = append(args, "%"+searchQuery+"%")
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
		return nil, fmt.Errorf("invalid sort parameter")
	}

	limitStr := queryParams.Get("limit")
	if limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit < 0 {
			return nil, fmt.Errorf("invalid limit value (must be a non-negative integer)")
		}
		baseQuery += fmt.Sprintf(" LIMIT $%d", argCounter)
		args = append(args, limit)
		argCounter++
	}
	offsetStr := queryParams.Get("offset")
	if offsetStr != "" {
		offset, err := strconv.Atoi(offsetStr)
		if err != nil || offset < 0 {
			return nil, fmt.Errorf("invalid offset value (must be a non-negative integer)")
		}
		baseQuery += fmt.Sprintf(" OFFSET $%d", argCounter)
		args = append(args, offset)
	}

	rows, err := conn.Query(context.Background(), baseQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	vulns := make([]Vulnerability, 0)
	for rows.Next() {
		var vuln Vulnerability
		err := rows.Scan(&vuln.ID, &vuln.Title, &vuln.Description, &vuln.Source, &vuln.Date, &vuln.RansomwareUse, &vuln.DueDate, &vuln.ThreatIndex)
		if err != nil {
			return nil, err
		}
		vulns = append(vulns, vuln)
	}
	return vulns, rows.Err()
}

func getVulnerabilities(w http.ResponseWriter, r *http.Request, conn *pgx.Conn) {
	vulns, err := queryVulnerabilities(conn, r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vulns)
}

func getDashboard(w http.ResponseWriter, r *http.Request, conn *pgx.Conn) {
	queryParams := r.URL.Query()
	sortVal := queryParams.Get("sort")
	if sortVal == "" {
		queryParams.Set("sort", "threat_index")
	}
	limitValue := queryParams.Get("limit")
	if limitValue == "" {
		limitVal := "40"
		queryParams.Set("limit", limitVal)
	}
	limit, err := strconv.Atoi(queryParams.Get("limit"))
	if err != nil || limit <= 0 {
		http.Error(w, "Invalid limit value", http.StatusBadRequest)
		return
	}
	page := 1
	pageValue := queryParams.Get("page")
	if pageValue != "" {
		page, err = strconv.Atoi(pageValue)
		if err != nil || page < 1 {
			http.Error(w, "Invalid page value", http.StatusBadRequest)
			return
		}
	}
	queryParams.Set("limit", strconv.Itoa(limit+1))
	queryParams.Set("offset", strconv.Itoa((page-1)*limit))
	vulns, err := queryVulnerabilities(conn, queryParams)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hasNext := len(vulns) > limit
	if hasNext {
		vulns = vulns[:limit]
	}

	totalCount := len(vulns)
	var highestThreatIndex float64
	var ransomwareCount int

	for _, v := range vulns {
		if v.ThreatIndex > highestThreatIndex {
			highestThreatIndex = v.ThreatIndex
		}
		if strings.EqualFold(v.RansomwareUse, "Known") || (v.RansomwareUse != "Unknown" && v.RansomwareUse != "" && v.RansomwareUse != "None") {
			ransomwareCount++
		}
	}
	averageScore := 0.0
	if totalCount > 0 {
		var totalScore float64
		for _, v := range vulns {
			totalScore += v.ThreatIndex
		}
		averageScore = totalScore / float64(totalCount)
	}

	renderTemplate(w, "dashboard", map[string]interface{}{
		"Title":              "Threat Dashboard",
		"Vulnerabilities":    vulns,
		"Search":             queryParams.Get("search"),
		"MinScore":           queryParams.Get("min_score"),
		"Sort":               queryParams.Get("sort"),
		"Limit":              strconv.Itoa(limit),
		"TotalCount":         totalCount,
		"HighestThreatIndex": highestThreatIndex,
		"AverageScore":       averageScore,
		"RansomwareCount":    ransomwareCount,
		"Page":               page,
		"HasPrevious":        page > 1,
		"HasNext":            hasNext,
		"PreviousURL":        dashboardPageURL(queryParams, page-1, limit),
		"NextURL":            dashboardPageURL(queryParams, page+1, limit),
	})
}

func dashboardPageURL(queryParams url.Values, page, limit int) string {
	pageParams := url.Values{}
	for key, values := range queryParams {
		if key != "offset" && key != "page" && key != "limit" {
			pageParams[key] = append([]string(nil), values...)
		}
	}
	pageParams.Set("page", strconv.Itoa(page))
	pageParams.Set("limit", strconv.Itoa(limit))
	return "/?" + pageParams.Encode()
}

func getVulnerability(w http.ResponseWriter, r *http.Request, conn *pgx.Conn) {
	cveID := strings.TrimPrefix(r.URL.Path, "/vulnerabilities/")
	if cveID == "" {
		http.NotFound(w, r)
		return
	}

	var vuln Vulnerability
	err := conn.QueryRow(context.Background(),
		"SELECT cve_id, title, description, source, date::text, ransomware_use, due_date, threat_index FROM vulnerabilities WHERE cve_id = $1",
		cveID,
	).Scan(&vuln.ID, &vuln.Title, &vuln.Description, &vuln.Source, &vuln.Date, &vuln.RansomwareUse, &vuln.DueDate, &vuln.ThreatIndex)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	renderTemplate(w, "detail", map[string]interface{}{
		"Title":         vuln.ID,
		"Vulnerability": vuln,
	})
}

func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	parsedTemplate, err := template.New("layout.html").Funcs(template.FuncMap{
		"add": func(left, right int) int {
			return left + right
		},
	}).ParseFiles(
		"templates/layout.html",
		fmt.Sprintf("templates/%s.html", tmpl),
		"templates/vulnerability-row.html",
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = parsedTemplate.ExecuteTemplate(w, "layout.html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
