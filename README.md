# OVH Dedicated — CLI + Web API (Flask)

**Python**: 3.12+  
**Package manager**: [uv](https://github.com/astral-sh/uv)

This tool signs OVH v1 requests and exposes:
- **CLI**:
  - `list-servers` → `GET /dedicated/server`
  - `server-info` → `GET /dedicated/server/{serviceName}` (+ optional `--field` dot-path)
- **Web API** (Flask):
  - `/healthz`
  - `/api?command=list-servers`
  - `/api?command=server-info&serverName=...&field=...`
  - Credentials via query (`appKey/appSecret/consumerKey`) **or** via `?apikey=` which loads env credentials

> The script file is `ovh_dedicated.py`. Keep it next to this `pyproject.toml`.

---

## 1) Setup with `uv`

```bash
# create in-project venv
uv venv
# install deps from pyproject
uv sync

