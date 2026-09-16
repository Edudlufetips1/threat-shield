# threat-shield

Cybersecurity threat-intelligence and alerting system. Collects vulnerability data (starting with CISA KEV), normalizes and stores it, prioritizes critical/actively exploited vulnerabilities, and will expose an API/dashboard for current threats, history, and alerts.

Status: early development.

## What this does

(placeholder — 2-3 sentences, your own words: what problem this solves, who'd use it, why "shield" and not just "dashboard")

## Architecture

(placeholder — brief walkthrough of the pipeline: collector -> scoring -> storage -> API/dashboard. Maybe a small diagram later.)

## Requirements

- Go (version?)
- Python (version?)
- Docker / Docker Compose
- PostgreSQL (via the provided docker-compose, or your own instance)

## Setup (crude list, reword this whole section)

1. Clone the repo.
2. Copy/create a `.env` file in the project root with:
   - `POSTGRES_USER`
   - `POSTGRES_PASSWORD`
   - `POSTGRES_DB`
   - `API_KEY` (shared secret the collector uses to authenticate to the API)
3. Start Postgres: `docker compose up -d`
4. Apply the schema: run `db/schema.sql` against the running database (e.g. via `psql`) — not applied automatically.
5. Start the Go server: `go run .` (listens on `:8080`, runs an initial CISA KEV collection immediately, then every 10 minutes after)
6. Visit `http://localhost:8080` for the dashboard.
7. (Optional) Manually trigger a collection instead of waiting: `python collector/collector.py`

## API

(placeholder — list endpoints: GET /api/vulnerabilities, POST /api/vulnerabilities, GET /vulnerabilities/{id}, query params supported)

## Testing

(placeholder — `go test ./...`, `pytest collector/`)

## Roadmap / Status

(placeholder — link or summarize what's done vs. planned; keep this short, the private JOURNAL/PROGRESS_REPORT have the full detail)

## License

(placeholder)
