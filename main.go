package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Edudlufetips1/threat-shield/internal/collector"
	"github.com/Edudlufetips1/threat-shield/internal/db"
	"github.com/Edudlufetips1/threat-shield/internal/scoring"
	"github.com/Edudlufetips1/threat-shield/internal/worker"

	"github.com/joho/godotenv"
)

func main() {
	scorer := scoring.ThreatScorer{
		BaseIndex:     23.17,
		ScalingScalar: 46.08,
		FallbackHits:  15.0,
	}
	fmt.Println("Threat Pipeline active on port 8080... Waiting for data.")
	err := godotenv.Load()
	if err != nil {
		fmt.Println("No .env file found. Using existing environment variables.")
	}
	conn, err := db.Connect(context.Background())
	if err != nil {
		fmt.Println("Failed to connect to the database:", err)
		return
	}
	defer conn.Close(context.Background())
	worker.StartBackgroundCollector(context.Background(), 10*time.Minute, func(ctx context.Context) error {
		if err := collector.CollectData(ctx, conn, &scorer, collector.KEV_URL); err != nil {
			fmt.Println("Failed to collect data:", err)
			return err
		}
		return nil
	})

	http.HandleFunc("/api/vulnerabilities", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			getVulnerabilities(w, r, conn)
			return
		}
		ingestThreat(w, r, conn, &scorer)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		getDashboard(w, r, conn)
	})
	http.HandleFunc("/vulnerabilities/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		getVulnerability(w, r, conn)
	})
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.ListenAndServe(":8080", nil)
}
