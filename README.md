# Threat Shield

Threat Shield is an automated system that ingests the Cybersecurity and Infrastructure Security Agency (CISA)'s Known Exploited Vulnerabilities (KEV) catalog, scores each vulnerability, and stores the results in PostgreSQL. When a new vulnerability is detected, it sends a webhook notification.

The system runs as a background process. It periodically fetches the CISA feed, processes new or updated records, and exposes the data through a REST API and web interface.

---

## Architecture

```text
[CISA Feed]
     │
     ▼
[Collector] ──► [Threat Scorer]
                      │
                      ▼
               [PostgreSQL]
                      │
         ┌────────────┴────────────┐
         ▼                         ▼
[New Record Check]           [API / Web UI]
         │
         ▼ (if new)
[Webhook Alert]
```

**Collector**  
Periodically fetches the CISA KEV catalog on a configurable interval.

**Threat Scorer**  
Calculates a risk score for each vulnerability based on available exploitation and impact data.

**Storage**  
Records are written to PostgreSQL using an idempotent upsert (`INSERT ... ON CONFLICT DO UPDATE`). New insertions are detected using `RETURNING (xmax = 0)`.

**Alerting**  
When a new vulnerability is inserted, a webhook notification is sent to a configured endpoint.

**API & Web UI**  
The full dataset is available through REST endpoints and a basic web interface.
---

### Required

- **Go 1.26.8**, matching the version declared in `go.mod`.
- **Python 3.13.x**, matching the runtime environment and dependencies.
- **Docker Engine** with the Docker Compose plugin, used to run PostgreSQL 15.
- Internet access to retrieve the CISA KEV feed while collecting data.

Go dependencies are defined in `go.mod` and downloaded automatically by Go. PostgreSQL runs in Docker by default; a host PostgreSQL instance can be used only if it is available at `localhost:5432` with the configured credentials.

### Optional Python tools

The running Go service includes its own collector, so Python is not required for normal operation. Python 3.9 or later is needed only for the standalone client in `collector/` and the calibration utility.

Install the standalone client and test dependencies with:

```bash
python -m pip install requests python-dotenv pytest
```

The calibration utility uses only the Python standard library.

## Quick start

1. Clone the repository and enter it.

     ```bash
     git clone https://github.com/Edudlufetips1/threat-shield.git
     cd threat-shield
     ```

2. Create a `.env` file in the project root. Choose a strong `API_KEY` before exposing the service beyond your local machine.

     ```env
     POSTGRES_USER=user
     POSTGRES_PASSWORD=password
     POSTGRES_DB=threat_shield_db
     API_KEY=replace-with-a-long-random-secret

     # Optional: receives a JSON webhook message when a CVE is first inserted.
     # ALERT_WEBHOOK_URL=https://your-webhook-endpoint.example
     ```

     The database variables have the shown defaults when omitted. `API_KEY` has no default: configure it before using the API or standalone Python client. Keep `.env` private; it is excluded from version control.

3. Start PostgreSQL.

     ```bash
     docker compose up -d
     ```

4. Initialize the schema. This is required once for a new database and can be run again safely.

     ```bash
     docker compose exec -T db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" < db/schema.sql
     ```

     If the variables exist only in `.env`, load them into your shell first or substitute the values directly. For the example configuration above:

     ```bash
     docker compose exec -T db psql -U user -d threat_shield_db < db/schema.sql
     ```

5. Start the service.

     ```bash
     go run .
     ```

The server listens on `http://localhost:8080`. The dashboard is public at that address. The collector runs in the background every 10 minutes; it does not perform an immediate collection at startup.

To collect immediately, in a separate terminal run:

```bash
go run ./cmd/refresh
```

## Configuration

| Variable | Required | Purpose |
| --- | --- | --- |
| `POSTGRES_USER` | Yes for Docker Compose | PostgreSQL username. Defaults to `user` in the Go service. |
| `POSTGRES_PASSWORD` | Yes for Docker Compose | PostgreSQL password. Defaults to `password` in the Go service. |
| `POSTGRES_DB` | Yes for Docker Compose | PostgreSQL database name. Defaults to `threat_shield_db` in the Go service. |
| `API_KEY` | Yes for API access | Shared secret required in the `X-API-Key` header for both API routes. |
| `ALERT_WEBHOOK_URL` | No | Endpoint notified when a CVE is first inserted. The payload format is compatible with Discord-style webhooks. |

If `ALERT_WEBHOOK_URL` is not set, data collection still succeeds; alert delivery is skipped and recorded in the server log.

## API and dashboard

The API requires `X-API-Key: <API_KEY>`. The dashboard and vulnerability detail pages do not currently require authentication.

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/` | Dashboard with filters and pagination. |
| `GET` | `/vulnerabilities/{cve_id}` | HTML detail page for a CVE. |
| `GET` | `/api/vulnerabilities` | Returns vulnerabilities as JSON. |
| `POST` | `/api/vulnerabilities` | Accepts a JSON array of vulnerability records for scoring and storage. |

`GET /api/vulnerabilities` supports the following query parameters:

| Parameter | Accepted values | Default |
| --- | --- | --- |
| `min_score` | Number from `0` to `100` | None |
| `search` | Text matched against CVE ID, title, and description | None |
| `sort` | `threat_index`, `threatIndex`, `cve_id`, `cveId`, `due_date_asc`, or `due_date_desc` | `threat_index` |
| `limit` | Non-negative integer | None for the API; `40` for the dashboard |
| `offset` | Non-negative integer | None |

Example API request:

```bash
curl -H "X-API-Key: $API_KEY" "http://localhost:8080/api/vulnerabilities?min_score=75&limit=20"
```

## Standalone Python collector

`collector/collector.py` retrieves the CISA KEV feed and posts normalized records to the local API. Start the Go service first, ensure the same `API_KEY` is available in `.env`, then run:

```bash
python collector/collector.py
```

The script targets `http://localhost:8080/api/vulnerabilities`. It is useful for manual submissions but is not necessary when the Go service scheduler is running.

## Development and testing

Run the Go test suite:

```bash
go test ./...
```

Some Go tests exercise PostgreSQL storage and collection paths. Start the Compose database and apply the schema with the same `.env` configuration before running the full suite.

Run the Python tests after installing the optional Python dependencies:

```bash
python -m pytest collector/
```

The project also includes `calibrate_threat_index.py`, a development-only utility for reviewing raw scoring output and suggesting scoring parameters. It is not part of the normal application workflow.

## Current scope

Implemented capabilities include CISA KEV collection, score calculation, PostgreSQL persistence, history records, API-key-protected API access, a basic dashboard, and optional new-record webhook alerts. Additional data sources, alert integrations, and hardened deployment configuration are outside the current scope.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
```
