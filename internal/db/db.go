package db

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
)

func Connect(ctx context.Context) (*pgx.Conn, error) {
	_ = godotenv.Load()
	user := os.Getenv("POSTGRES_USER")
	if user == "" {
		user = "user"
	}
	pass := os.Getenv("POSTGRES_PASSWORD")
	if pass == "" {
		pass = "password"
	}
	dbname := os.Getenv("POSTGRES_DB")
	if dbname == "" {
		dbname = "threat_shield_db"
	}
	connString := fmt.Sprintf(
		"postgres://%s:%s@localhost:5432/%s",
		user,
		pass,
		dbname,
	)
	return pgx.Connect(ctx, connString)
}
