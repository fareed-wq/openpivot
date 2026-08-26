# OpenPivot

OpenPivot is a lightweight OSINT and infrastructure intelligence platform for collecting and correlating publicly available technical information about domains, public IP addresses, networks, certificates, DNS, and related infrastructure.

## Project Status

🚧 Early development

## Initial MVP

The first version will support:

- Domain investigation
- Public IPv4 investigation
- DNS intelligence
- RDAP registration intelligence
- TLS certificate metadata
- HTTP metadata
- Email security records
- IP and ASN intelligence
- Infrastructure correlation
- Graceful handling of unavailable data sources

## Principles

OpenPivot is designed as an intelligence and investigation platform, not a vulnerability scanner.

The project will:

- Use publicly available technical data
- Use lightweight and zero-cost data sources where possible
- Block private and internal network targets
- Avoid intrusive scanning
- Avoid exploitation and brute force
- Avoid personal tracking
- Keep collectors modular and failure-isolated

## Technology

Frontend:
- React
- Vite
- Tailwind CSS

Backend:
- Python
- FastAPI

Database:
- Not required for the initial anonymous MVP

## Development Workflow

```text
dev
 ↓
Pull Request
 ↓
main