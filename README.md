# OSINT Enricher

**OSINT Enricher** is a microservice that ingests real-time OSINT feeds via RSS/Atom, stores raw entries in a Postgres database, enriches them with AI-driven cybersecurity analysis using OpenAI, and indexes structured results and vectors in ChromaDB for fast retrieval and semantic search.

## Features

- Pulls from multiple RSS/Atom feeds on a schedule
- Stores raw feed entries in `current` and `archive` tables in Postgres
- Enriches new entries via a ChatOpenAI-powered pipeline, extracting:
  - Severity level, confidence, recommended actions
  - Key IOCs, affected sectors, mitigation strategies
  - Potential threat actors, historical context, impact summary
  - Relevance score, CVE references, and more
- Persists structured analysis in `analysis` table
- Builds vector embeddings in ChromaDB for semantic similarity queries
- Containerized with Docker Compose for easy deployment

## Prerequisites

- Docker & Docker Compose
- (Optional) Python 3.11+ and virtual environment for local development
- OpenAI API Key
- A running Postgres instance (local or remote)
- (Optional) ChromaDB running via included Docker service

## Setup

1. **Clone the repo**  
   ```bash
   git clone https://github.com/miketigerblue/osint-enricher.git
   cd osint-enricher
   ```

2. **Environment Variables**  
   Copy `.env.example` to `.env` and fill in:
   ```env
   OPENAI_API_KEY=sk-...
   DATABASE_URL=postgresql://user:password@db:5432/osint
   ```

3. **Build & Run**  
   ```bash
   docker-compose up --build
   ```
   - `db_dummy` service simulates Postgres for local testing.
   - `enricher` service will automatically connect, initialize tables, and run enrichment.

## Local Development

```bash
# Create and activate venv
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run locally
OPENAI_API_KEY=... DATABASE_URL=... python main.py
```

## Database Schema

- `current`: stores the latest raw entries
- `archive`: historical raw entries
- `analysis`: structured AI-enriched data

Use `psql` or `pgAdmin` to explore tables.

## File Structure

```
.
├── enricher/
│   ├── analysis_utils.py
│   ├── chromadb_utils.py
│   ├── config.py
│   ├── database.py
│   ├── Dockerfile
│   ├── main.py
│   └── requirements.txt
├── .env                  # local env (gitignored)
├── .env.example          # template for required env vars
├── .gitignore
├── docker-compose.yml
└── README.md

```

## CI/CD

The GitHub Actions workflow in `.github/workflows/ci.yml` will:

- Lint Python code with `flake8`
- Run unit tests (if any)
- Build & push Docker images

## Commit Message

When merging this README into `main`, use:

```
🎉 docs: add comprehensive README with setup, usage, and architecture
```

## License

MIT © Your Name
