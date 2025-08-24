# OVH Dedicated — CLI + Web API (Flask)

Minimal, production-friendly client for **OVHcloud v1 API** (Dedicated Servers).  
Provides a **CLI** and a tiny **Web API** with proper v1 request signing, flexible config, and Docker packaging.

---

## Features

- **OVH v1 signing** (`X-Ovh-*` headers) with **time skew** handling via `GET /auth/time` and **one retry** on invalid signature.
- **Commands**
  - `list-servers` → `GET /dedicated/server` (array of service names)
  - `server-info` → `GET /dedicated/server/{serviceName}`
  - `--field <dot.path>` to extract a single JSON value (dot-path).
- **Output formats**: `json` (compact), `pretty` (indented), `flat` (dot-keys `k=v` lines).
- **Config precedence**: **CLI args > environment variables > `.env`** (auto-loaded; never overrides real env).
- **Web API** (Flask):
  - Endpoints: `/healthz`, `/api`
  - Credentials via query (`appKey/appSecret/consumerKey`) **or** `?apikey=` to unlock env-based creds.
  - `output-format` query param for `json` | `pretty` | `flat`.
- **Portable**: run **locally** (uv/pip), as a **Docker** container (gunicorn), or under **Passenger** (cPanel/o2switch) via `passenger_wsgi.py`.

---

## Requirements

- Python **3.12+**
- OVH credentials:
  - **Application Key** (AK)
  - **Application Secret** (AS)
  - **Consumer Key** (CK) with minimal scopes:
    - `GET /dedicated/server`
    - `GET /dedicated/server/*`

Quick CK creation:
```bash
AK="AK_xxx"
curl -s -X POST -H "X-Ovh-Application: ${AK}" -H "Content-Type: application/json" \
  https://eu.api.ovh.com/1.0/auth/credential \
  -d '{
    "accessRules": [
      {"method":"GET","path":"/dedicated/server"},
      {"method":"GET","path":"/dedicated/server/*"}
    ]
  }'
# Open "validationUrl" from the output and validate to activate the CK.

