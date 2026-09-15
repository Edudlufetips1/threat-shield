package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/joho/godotenv"

	"github.com/jackc/pgx/v5"
)

type Vulnerability struct {
	ID            string `json:"id"`
	Title         string `json:"title"`
	Description   string `json:"description"`
	Source        string `json:"source"`
	Date          string `json:"date"`
	RansomwareUse string `json:"ransomware_use"`
	DueDate       string `json:"due_date"`
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

func connectDB() (*pgx.Conn, error) {
	conn, err := pgx.Connect(context.Background(), "postgres://"+os.Getenv("POSTGRES_USER")+":"+os.Getenv("POSTGRES_PASSWORD")+"@localhost:5432/"+os.Getenv("POSTGRES_DB"))
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func main() {
	scorer := ThreatScorer{
		BaseIndex:     23.17,
		ScalingScalar: 46.08,
		FallbackHits:  15.0,
	}
	fmt.Println("Threat Pipeline active on port 8080... Waiting for data.")
	err := godotenv.Load()
	if err != nil {
		fmt.Println("No .env file found. Using existing environment variables.")
	}
	conn, err := connectDB()
	if err != nil {
		fmt.Println("Failed to connect to the database:", err)
		return
	}
	defer conn.Close(context.Background())

	http.HandleFunc("/api/vulnerabilities", func(w http.ResponseWriter, r *http.Request) {
		ingestThreat(w, r, conn, &scorer)
	})
	http.ListenAndServe(":8080", nil)
}
