# ScamRatio New Backend

Fresh backend for ScamRatio. It does not use VirusTotal.

## API

- `GET /api/health`
- `GET /api/check?url=https://example.com`
- `POST /api/check` with JSON `{ "url": "https://example.com" }`

## Detection sources

- URLhaus community API
- PhishTank API
- ThreatFox community API
- DNS resolution
- TLS certificate checks
- RDAP registration data

A source returning no match is not treated as proof that a website is safe.

## Environment variables

Set these in Render, not in GitHub:

- `URLHAUS_AUTH_KEY`
- `PHISHTANK_APP_KEY` (optional)
- `THREATFOX_AUTH_KEY` (optional; defaults to URLHAUS_AUTH_KEY)

Never commit `.env`.
