# OpenPivot

OpenPivot is a lightweight technical OSINT and public-infrastructure intelligence platform for investigating domains and public IPv4 addresses. It gathers, structures, and correlates publicly available technical information using passive, non-intrusive collection — with a zero-cost architecture that requires no paid APIs, no AI services, and no GPU.

## Purpose

OpenPivot collects and correlates publicly available technical data about:

- Domains and DNS records
- Email security configuration (SPF, DMARC, MX)
- Domain registration data (RDAP)
- TLS certificates
- HTTP response metadata
- Public IPv4 network allocations
- Reverse DNS hostnames
- ASN and routing ownership
- Related infrastructure relationships

All data comes from public protocols and registries. OpenPivot does not perform vulnerability scanning, exploitation, or personal tracking.

## Key Features

- Domain and public IPv4 investigation
- Strict target validation (private/internal targets blocked)
- DNS intelligence (A, AAAA, MX, NS, TXT, CNAME, CAA)
- SPF / DMARC / MX provider visibility
- Domain RDAP registration intelligence
- TLS certificate intelligence (chain, SAN, expiry, verification)
- Safe HTTP metadata collection (headers, redirects, server identity)
- IP network RDAP (allocation, organization, prefixes)
- Reverse DNS
- IP to ASN discovery (Team Cymru + RDAP)
- ASN registration intelligence
- Infrastructure correlation engine
- Structured investigation report UI
- Graceful collector failure isolation
- SSRF / DNS-rebinding protections on all outbound connections

## Infrastructure Correlation

OpenPivot automatically discovers relationships across collectors:

```text
Domain → IP → ASN → Organization
```

Example relationships:

- Domain → Nameserver
- Domain → Mail Server
- Domain → Certificate
- Certificate → SAN Hostname
- IP → Reverse DNS Hostname
- IP → ASN → Organization

In v0.1, correlation is single-depth. OpenPivot does not automatically perform recursive investigation of discovered infrastructure.

## Tech Stack

**Frontend:**
- React
- Vite
- Tailwind CSS

**Backend:**
- Python
- FastAPI
- dnspython
- cryptography

**Database:** Not required for v0.1. All investigations are stateless.

## Requirements

- Python 3.13+
- Node.js
- npm
- Git

## Setup (Windows)

From the repository root:

**Create and activate the backend virtual environment:**

```powershell
python -m venv backend\.venv
backend\.venv\Scripts\activate
```

**Install backend dependencies:**

```powershell
pip install -r backend\requirements.txt
```

**Install frontend dependencies:**

```powershell
cd frontend
npm install
cd ..
```

## Run the Backend

```powershell
cd backend
.venv\Scripts\activate
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

| Endpoint | URL |
|---|---|
| Backend | http://127.0.0.1:8000 |
| Swagger docs | http://127.0.0.1:8000/docs |
| Health check | http://127.0.0.1:8000/health |

## Run the Frontend

```powershell
cd frontend
npm run dev
```

Frontend: http://127.0.0.1:8080

The Vite dev server proxies `/api` requests to the local FastAPI backend automatically. Do not hardcode backend URLs in the frontend.

## Usage

Enter a target in the investigation form and submit.

**Supported inputs:**

```
example.com
8.8.8.8
```

**Not supported:**

```
https://example.com    (URLs are not accepted)
localhost              (private/internal targets blocked)
192.168.1.1            (RFC1918 addresses blocked)
```

OpenPivot currently accepts domain names and globally routable public IPv4 addresses.

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | API status |
| `GET` | `/health` | Health check |
| `POST` | `/validate` | Validate and classify a target |
| `POST` | `/investigate` | Run a full investigation |
| `GET` | `/docs` | Swagger UI |

**Example — POST /investigate:**

```json
{
  "target": "example.com"
}
```

The response contains structured collector results, collector statuses, and a correlation graph with entities and relationships.

## Investigation Flow

```text
Input
  ↓
Target Validation
  ↓
Collector Routing (domain or IPv4)
  ↓
Relevant Collectors (parallel, failure-isolated)
  ↓
Correlation Engine
  ↓
Structured Investigation Report
```

**Domain investigation runs:**

DNS → Email Security → RDAP → TLS → HTTP Metadata

**IPv4 investigation runs:**

Network RDAP + Reverse DNS → ASN Intelligence

Each collector runs independently. If one collector fails or times out, the others still return results and the investigation completes with a partial status.

## Safety and Scope

OpenPivot is designed for passive technical intelligence using publicly available infrastructure information.

**v0.1 does NOT perform:**

- Vulnerability exploitation or testing
- Brute force or credential attacks
- Port scanning
- Content fuzzing or active payload testing
- Private-network reconnaissance
- Recursive crawling or spidering
- Personal or people-focused OSINT
- Precise device or person geolocation

**Network safety controls:**

- Localhost, RFC1918, link-local, and non-global destinations are blocked
- All outbound HTTP and RDAP connections validate the destination IP before connecting
- Redirects are bounded and each hop is revalidated
- Socket connections use pre-resolved validated IPs to prevent DNS rebinding

## Privacy

OpenPivot intentionally focuses on organization-level and network-level registration data.

It does not intentionally expose:

- Registrant personal names
- Personal email addresses
- Phone numbers
- Street addresses

Individual-kind RDAP entities are filtered from results. Country fields represent registration or allocation context, not precise physical location.

## Testing

**Run backend tests from the repository root:**

```powershell
backend\.venv\Scripts\python.exe -m pytest backend\tests
```

Current verified result: 85 backend tests passing.

**Run frontend production build:**

```powershell
cd frontend
npm run build
```

There are no automated frontend UI tests in v0.1.

## Project Status

**OpenPivot v0.1 MVP**

Implemented:

- Domain investigations (DNS, email security, RDAP, TLS, HTTP metadata)
- IPv4 investigations (network RDAP, reverse DNS, ASN intelligence)
- Infrastructure correlation engine
- Investigation report UI
- SSRF / DNS-rebinding network protections
- 85 backend tests

**Possible future work:**

- Optional authentication and investigation history
- Caching and rate limiting
- Optional public threat-intelligence adapters
- Certificate transparency log integration
- JSON / CSV / PDF report exports
- Bounded collector concurrency
- Controlled pivot workflows

No timelines are committed for future items.

## Zero-Cost Design

The current MVP is built around:

- Free public protocols and data sources (DNS, RDAP, TLS, HTTP)
- No paid API requirement
- No AI API requirement
- No local LLM or GPU requirement
- Lightweight local development with standard tools

## Development Workflow

```text
dev → Pull Request → main
```

- Feature development occurs on the `dev` branch
- No direct feature pushes to `main`
- Small, focused commits preferred