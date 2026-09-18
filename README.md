# 🛡️ Threat Shield

Threat Shield collects vulnerabilities from CISA's Known Exploited Vulnerabilities (KEV) catalog, scores their relative risk, stores them in PostgreSQL, and displays the results through a web dashboard and REST API.

---

## 🎯 Motivation

Security teams often face noisy vulnerability feeds and slow manual triage. Threat Shield turns the CISA KEV catalog into scored, searchable, and actionable vulnerability data.

---

## ⚙️ Quick Start

### Requirements

- Go 1.26.8
- Docker Engine with Docker Compose
- Internet access

*(Python is optional and only needed for the standalone client and calibration utility.)*

### 1. Clone the repository

```bash
git clone https://github.com/Edudlufetips1/threat-shield.git
cd threat-shield
```

### 2. Create your environment file

Create a `.env` file in the project root:

```env
POSTGRES_USER=user
POSTGRES_PASSWORD=password
POSTGRES_DB=threat_shield_db
API_KEY=replace-with-a-long-random-secret
```

> 🔒 **Note:** Keep this file private. It is excluded from version control.

### 3. Start PostgreSQL

```bash
docker compose up -d
```

### 4. Initialize the database

Run this once for a new database (it can also safely be re-run later):

```bash
docker compose exec -T db psql -U user -d threat_shield_db < db/schema.sql
```

### 5. Start Threat Shield

```bash
go run .
```

Open the dashboard at **http://localhost:8080**.

The service collects the CISA KEV catalog when it starts, then repeats collection every 10 minutes. To trigger a collection manually, run this in a second terminal:

```bash
go run ./cmd/refresh
```

---

## 📦 Usage

Once Threat Shield is running, you can interact with it through the dashboard, the REST API, and optional webhook alerts.

### Dashboard

Open **http://localhost:8080** in your browser to view scored vulnerabilities, browse newly discovered entries, and review alert history.

### REST API

Query the API directly. Authenticated endpoints require your `API_KEY`:

```bash
curl -H "Authorization: Bearer $API_KEY" http://localhost:8080/api/vulnerabilities
```

### Manual refresh

Trigger an on-demand collection of the CISA KEV catalog:

```bash
go run ./cmd/refresh
```

### Webhook alerts

Set `ALERT_WEBHOOK_URL` in your `.env` file to receive a POST request whenever a new vulnerability is discovered.

### What it does

Threat Shield runs three main processes:

* Collects vulnerability data from CISA's KEV catalog
* Scores and stores vulnerabilities in PostgreSQL
* Displays and alerts on newly discovered vulnerabilities through the dashboard, API, and optional webhooks

---

## 🏗️ Architecture

```text
  CISA Feed
    │
    ▼
Collector → Threat Scorer → PostgreSQL
                              │
                 ┌────────────┴────────────┐
                 ▼                         ▼
             REST API                  Web UI
                 │
                 ▼
           Webhook alerts
```

---

## 🎛️ Configuration

The following environment variables are supported:

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `POSTGRES_USER` | PostgreSQL username | `user` |
| `POSTGRES_PASSWORD` | PostgreSQL password | `password` |
| `POSTGRES_DB` | PostgreSQL database name | `threat_shield_db` |
| `API_KEY` | API and client authentication | **Required** |
| `ALERT_WEBHOOK_URL` | Endpoint for new-vulnerability alerts | *Optional* |

*(Note: The database can also run on a local PostgreSQL installation at `localhost:5432` if preferred.)*

---

## Optional Python tools

Python is not required to run the main Go service. It is only needed for the standalone client in `collector/` and the calibration utility:

```bash
python -m pip install requests python-dotenv pytest
```

*(The calibration utility uses only the Python standard library.)*

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check out the issues page or open a pull request if you'd like to suggest improvements.

---

## 📄 License

This project is licensed under the MIT License. See LICENSE for details.
