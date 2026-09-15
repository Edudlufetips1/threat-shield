package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/joho/godotenv"

	"github.com/jackc/pgx/v5"
)

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
