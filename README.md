# OpenPivot

Public technical infrastructure intelligence and correlation platform for domains and public IP addresses.

## Overview

OpenPivot is a platform that collects, normalizes, correlates, and visualizes publicly available technical infrastructure data. It empowers users to map digital footprints efficiently and securely.

Key principles:
- **Passive/Public Intelligence**: Data is sourced exclusively from public registries and protocols without active probing.
- **Controlled Investigation**: Investigations are explicitly user-driven, ensuring predictable and bound data collection.
- **Evidence-Based Correlation**: Infrastructure relationships are drawn directly from verifiable registry and protocol artifacts.
- **Strictly Non-Intrusive**: OpenPivot does not perform vulnerability exploitation, brute forcing, or intrusive scanning.

## Core Features

- **Domain Investigation**
- **Public IPv4 Investigation**
- **DNS Intelligence**: Resolution, nameservers, TXT, CAA, etc.
- **Email Security Records**: SPF, DMARC, and MX providers.
- **Domain/IP RDAP**: Deep registry and allocation data.
- **TLS/Certificate Intelligence**: Issuers, SANs, and expiry data.
- **HTTP Metadata**: Safe, isolated web header and redirect collection.
- **ASN/Routing Intelligence**: Origin ASN and registration/network context.
- **Web Footprint Intelligence**:
  - Web metadata extraction (titles, canonicals, generators).
  - Technology detection (server, framework, CDN/proxy).
  - Evidence + confidence metrics for derived technologies.
- **Organization Technical Footprint**: Synthesized organization registry and network summaries.
- **Enhanced Cross-Source Correlation**: Multi-collector graph mapping.
- **Interactive Infrastructure Graph**: Visual relationship discovery.
- **Investigation Summary**: High-level status overview.
- **Collapsible Reports**: Modular sections open and close intuitively.
- **Controlled Pivot Actions**: Explicitly pivot into related domains and IPs.
- **One-step Back**: Navigate history safely.
- **Sticky Section Navigation**: Sticky report navigation for fast scrolling.
- **Copy Utilities**: One-click copying for artifacts.
- **Technical Raw Data**: Inspect underlying JSON structures seamlessly.

## Correlation Examples

OpenPivot automatically discovers evidence-backed relationships across separate collectors, unifying disparate protocol data:

- Domain → IP
- IP → ASN
- ASN → Organization
- Domain → Nameserver
- Domain → Mail Host
- Domain → Technology
- Domain → Organization

## Interactive Graph

The interactive infrastructure graph visualizes technical relationships natively in the browser.
- Supports smooth drag, pan, and zoom operations.
- Entities are rendered as selectable nodes categorized by type.
- Edges prominently feature relationship labels (e.g., esolves_to, uses_technology).
- Supports **controlled Pivot** directly from supported domain and IP nodes.

## Web Footprint Intelligence

OpenPivot automatically distills complex HTTP responses into structured metadata and technology identifications. Technology detection evaluates exact evidence (e.g., headers or HTML patterns) and asserts a confidence level (high, medium, low). This mechanism provides factual operational context and strictly avoids assigning arbitrary security or vulnerability scores.

## Organization Footprint

The Organization Technical Footprint dynamically derives an evidence-backed organization summary from the already collected data (Domain RDAP, IP RDAP, ASN Registration, DNS, and HTTP). It efficiently synthesizes organization names, IPs, prefixes, nameservers, mail hosts, and technologies without generating any additional network requests. Note that organization context markers (e.g., country codes) represent registry allocation contexts, not physical server locations.

## Architecture

**Frontend:** React, Vite, Tailwind CSS
**Backend:** Python, FastAPI
**Deployment:** Vercel

The platform follows a modular pipeline: input validation routes targets to relevant modular collectors (DNS, RDAP, HTTP, etc.) which are orchestrated per investigation with isolated failures and strict timeouts. Results are merged and passed to the correlation engine, which resolves nodes and relationships for the frontend React application.

## Safety & Scope

OpenPivot is designed for safe, passive technical intelligence:

- **Public targets only**: Explicitly accepts only public domains and globally routable public IPv4 addresses.
- **Private targets blocked**: Localhost, RFC1918, link-local, and non-global destinations are rejected.
- **SSRF protections**: All outbound connections pre-resolve and validate destinations to prevent DNS-rebinding and Server-Side Request Forgery.
- **Bounded execution**: Network timeouts, max redirects, and max response sizes are strictly enforced.
- **Isolated failures**: Individual collector timeouts or errors do not crash the investigation.
- **No recursive automatic pivots**: Pivots require explicit user interaction.
- **No active exploitation**: No fuzzing, payload injection, or port scanning.
- **No personal OSINT**: Built for technical infrastructure, not credential or people discovery.

## Project Structure

`	ext
backend/
  app/
    api/              # FastAPI route handlers
    core/             # Core application configurations
    intelligence/     # Data collectors, correlation, and synthesis engines
    models/           # Pydantic schemas
frontend/
  src/
    components/       # React UI components (Graph, Reports)
`

## Setup & Local Development (Windows)

From the repository root:

**Create and activate the backend virtual environment:**
`powershell
python -m venv backend\.venv
backend\.venv\Scripts\activate
`

**Install backend dependencies:**
`powershell
pip install -r backend\requirements.txt
`

**Install frontend dependencies:**
`powershell
cd frontend
npm install
cd ..
`

**Run the Backend:**
`powershell
cd backend
.venv\Scripts\activate
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
`

**Run the Frontend:**
`powershell
cd frontend
npm run dev
`
*(The Vite dev server runs on http://127.0.0.1:8080 and proxies /api requests to the local FastAPI backend)*

## Testing

**Backend Tests:**
`powershell
backend\.venv\Scripts\python.exe -m pytest backend\tests
`
*(Current verified status: 110 tests passing)*

**Frontend Build:**
`powershell
cd frontend
npm run build
`

## Deployment

OpenPivot is configured for seamless deployment to Vercel within a single Vercel project. The architecture utilizes a standard Vite frontend configuration, while the backend API routes are powered natively by Vercel Python Serverless Functions executing FastAPI.

## Project Status

OpenPivot operates as a working open-source technical OSINT portfolio project. It is continually refined to model safe, scalable, and modular intelligence gathering.
