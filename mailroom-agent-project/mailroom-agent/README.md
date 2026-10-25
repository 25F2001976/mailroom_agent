# Mailroom Action Gate Agent (ga5-mailroom-action-gate/v2)

This service provides an HTTPS mailroom agent meeting the GA5 specification:
1. `propose` operation:
   - Validates envelope and schema.
   - Computes canonical `inputDigest` over UTF-8 bytes of key-sorted, compact JSON dossiers.
   - Evaluates incoming dossiers and returns exactly one safe proposal per dossier with minimal valid evidence citations.
   - Persists evaluation state and verifier key.
   - Supports exact replay (HTTP 200) and conflicting content replay (HTTP 409).
2. `commit` operation:
   - Verifies each incoming Ed25519 signature against the registered JWK public key.
   - Validates proposal digests and receipts against persisted evaluation data.
   - Strictly marks outcomes as `executed` (when `accepted: true`) or `rejected`.
   - Returns terminal completion status.

## Deployment

Deploy using Docker or Render, or run locally:
```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```
