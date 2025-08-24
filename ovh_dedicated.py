#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ovh_dedicated.py — OVH Dedicated Servers CLI + Web API
Python >= 3.12

Configuration precedence (highest first):
1) CLI arguments
2) Process environment variables
3) .env file (auto-loaded via python-dotenv; does NOT override process env)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
import time
import typing as t
from dataclasses import dataclass

import requests
from flask import Flask, jsonify, request, Response, abort
from werkzeug.exceptions import HTTPException  # let 4xx bubble

# ---- .env auto-loading (no override of existing env) ----
try:
    from dotenv import load_dotenv, find_dotenv
    load_dotenv(find_dotenv(usecwd=True), override=False)
except Exception:
    pass

# ---------- Logging ----------
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("ovh_dedicated")

# ---------- Constants (read AFTER dotenv load) ----------
DEFAULT_API_BASE = os.environ.get("OVH_API_BASE", "https://eu.api.ovh.com")
DEFAULT_API_VERSION = os.environ.get("OVH_API_VERSION", "v1")
DEFAULT_OUTPUT_FORMAT = os.environ.get("DEFAULT_OUTPUT_FORMAT", "json").lower()
DEFAULT_SERVER_NAME = os.environ.get("DEFAULT_SERVER_NAME", "")

WEB_BIND = os.environ.get("WEB_BIND", "0.0.0.0")
WEB_PORT = int(os.environ.get("WEB_PORT", "8088"))
WEB_API_KEY = os.environ.get("WEB_API_KEY")  # optional


# ---------- Helpers ----------
def join_url(base: str, version: str, path: str) -> str:
    base = base.rstrip("/")
    version = version.strip("/")
    path = path if path.startswith("/") else f"/{path}"
    return f"{base}/{version}{path}"


def json_compact(obj: t.Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def flatten(obj: t.Any, parent_key: str = "", sep: str = ".") -> dict[str, t.Any]:
    items: dict[str, t.Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)
            items.update(flatten(v, new_key, sep=sep))
    elif isinstance(obj, list):
        for idx, v in enumerate(obj):
            new_key = f"{parent_key}{sep}{idx}" if parent_key else str(idx)
            items.update(flatten(v, new_key, sep=sep))
    else:
        items[parent_key] = obj
    return items


def select_field(obj: t.Any, field_path: str) -> t.Any:
    if not field_path:
        return obj
    parts = field_path.split(".")
    cur = obj
    for p in parts:
        if isinstance(cur, dict):
            if p not in cur:
                raise KeyError(f"Path not found: {field_path}")
            cur = cur[p]
        elif isinstance(cur, list):
            try:
                idx = int(p)
            except ValueError as exc:
                raise KeyError(f"Expected list index at '{p}' in {field_path}") from exc
            if idx < 0 or idx >= len(cur):
                raise KeyError(f"Index out of range at '{p}' in {field_path}")
            cur = cur[idx]
        else:
            raise KeyError(f"Cannot descend into scalar at '{p}' in {field_path}")
    return cur


# ---------- OVH Client ----------
@dataclass
class OvhCredentials:
    app_key: str
    app_secret: str
    consumer_key: str | None = None


class OvhClient:
    """Minimal OVH API v1 client with request signing."""

    def __init__(
        self,
        creds: OvhCredentials,
        api_base: str = DEFAULT_API_BASE,
        api_version: str = DEFAULT_API_VERSION,
        timeout: float = 20.0,
        session: requests.Session | None = None,
    ) -> None:
        self.creds = creds
        self.api_base = api_base.rstrip("/")
        self.api_version = api_version.strip("/")
        self.timeout = timeout
        self.sess = session or requests.Session()
        self._time_skew = 0
        self._last_sync = 0.0

    def _sync_time(self, force: bool = False) -> None:
        now = time.time()
        if not force and (now - self._last_sync) < 60:
            return
        url = join_url(self.api_base, self.api_version, "/auth/time")
        r = self.sess.get(url, timeout=self.timeout)
        r.raise_for_status()
        ovh_ts = int(r.text.strip())
        self._time_skew = ovh_ts - int(now)
        self._last_sync = now
        logger.debug("Synced OVH time, skew=%ss", self._time_skew)

    def _ovh_timestamp(self) -> int:
        self._sync_time(force=False)
        return int(time.time()) + self._time_skew

    def _sign(self, method: str, full_url: str, body: str, timestamp: int) -> str:
        ck = self.creds.consumer_key or ""
        material = "+".join(
            [self.creds.app_secret, ck, method.upper(), full_url, body, str(timestamp)]
        )
        digest = hashlib.sha1(material.encode("utf-8")).hexdigest()
        return f"$1${digest}"

    def _headers(self, method: str, full_url: str, body: str) -> dict[str, str]:
        ts = self._ovh_timestamp()
        headers = {
            "X-Ovh-Application": self.creds.app_key,
            "X-Ovh-Timestamp": str(ts),
        }
        if self.creds.consumer_key:
            headers["X-Ovh-Consumer"] = self.creds.consumer_key
            headers["X-Ovh-Signature"] = self._sign(method, full_url, body, ts)
        if body:
            headers["Content-Type"] = "application/json"
        return headers

    def request(
        self, method: str, path: str, params: dict | None = None, data: dict | None = None
    ) -> t.Any:
        url = join_url(self.api_base, self.api_version, path)
        body = json_compact(data) if data is not None else ""
        headers = self._headers(method, url, body)
        logger.debug("Request %s %s params=%s body=%s", method, url, params, body)
        r = self.sess.request(
            method=method.upper(),
            url=url,
            params=params,
            data=body if body else None,
            headers=headers,
            timeout=self.timeout,
        )
        if r.status_code in (400, 401) and "Invalid signature" in r.text:
            logger.warning("Signature failed, re-syncing time and retrying once...")
            self._sync_time(force=True)
            headers = self._headers(method, url, body)
            r = self.sess.request(
                method=method.upper(),
                url=url,
                params=params,
                data=body if body else None,
                headers=headers,
                timeout=self.timeout,
            )

        r.raise_for_status()
        if r.text.strip() == "":
            return None
        try:
            return r.json()
        except json.JSONDecodeError:
            return r.text

    def list_servers(self) -> list[str]:
        return self.request("GET", "/dedicated/server")

    def server_info(self, service_name: str) -> dict:
        return self.request("GET", f"/dedicated/server/{service_name}")


# ---------- Formatting ----------
def format_output(data: t.Any, output_format: str) -> str:
    fmt = (output_format or "json").lower()
    if fmt == "json":
        return json_compact(data)
    if fmt == "pretty":
        return json.dumps(data, indent=2, ensure_ascii=False)
    if fmt == "flat":
        if isinstance(data, dict):
            fl = flatten(data)
            lines = [f"{k}={fl[k]}" for k in sorted(fl.keys())]
            return "\n".join(lines) + ("\n" if lines else "")
        if isinstance(data, list):
            if all(isinstance(x, str) for x in data):
                return "\n".join(data) + ("\n" if data else "")
            out_lines: list[str] = []
            for item in data:
                if isinstance(item, dict):
                    fl = flatten(item)
                    kv = " ".join(f"{k}={fl[k]}" for k in sorted(fl.keys()))
                    out_lines.append(kv)
                else:
                    out_lines.append(str(item))
            return "\n".join(out_lines) + ("\n" if out_lines else "")
        return str(data) + ("\n" if data is not None else "")
    raise ValueError(f"Unknown output format: {output_format}")


# ---------- CLI ----------
def build_client_from_sources(
    app_key: str | None,
    app_secret: str | None,
    consumer_key: str | None,
    prefer_env: bool = True,
) -> OvhClient:
    ek = app_key or (prefer_env and os.environ.get("OVH_APPLICATION_KEY"))
    es = app_secret or (prefer_env and os.environ.get("OVH_APPLICATION_SECRET"))
    ck = consumer_key or (prefer_env and os.environ.get("OVH_CONSUMER_KEY"))
    if not ek or not es:
        raise SystemExit("Missing OVH application key/secret (provide via args, env, or .env).")
    creds = OvhCredentials(app_key=ek, app_secret=es, consumer_key=ck)
    return OvhClient(creds=creds)


def cli_main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="OVH Dedicated Servers CLI + Web API")
    parser.add_argument("--application-key", "-K", dest="app_key", help="OVH Application Key")
    parser.add_argument("--application-secret", "-S", dest="app_secret", help="OVH Application Secret")
    parser.add_argument("--consumer-key", "-C", dest="consumer_key", help="OVH Consumer Key (optional, but required by most endpoints)")
    parser.add_argument("--server-name","-s",dest="server_name",default=DEFAULT_SERVER_NAME,help="Service name (e.g. ns31097497.ip-51-38-63.eu)")
    parser.add_argument("--output-format","-o",dest="output_format",default=DEFAULT_OUTPUT_FORMAT,choices=["json","pretty","flat"],help="Output format (default: json)")
    parser.add_argument("--field","-f",dest="field",help="Dot-path of a single field to extract (only for server-info)")
    parser.add_argument("--web",action="store_true",help="Run the embedded web API server (Flask). If used with a command, the web server starts AFTER the command finishes.")
    sub = parser.add_subparsers(dest="command", required=False)

    sub.add_parser("list-servers", help="List dedicated servers serviceNames")
    p_info = sub.add_parser("server-info", help="Get info for /dedicated/server/{serviceName}")
    p_info.add_argument("--server-name","-s",dest="server_name_arg",help="Service name override")

    args = parser.parse_args(argv)

    if not args.command and not args.web:
        parser.print_help()
        return 0

    exit_code = 0

    if args.command:
        client = build_client_from_sources(args.app_key, args.app_secret, args.consumer_key)
        try:
            if args.command == "list-servers":
                data = client.list_servers()
                sys.stdout.write(format_output(data, args.output_format))
            elif args.command == "server-info":
                srv = args.server_name_arg or args.server_name
                if not srv:
                    raise SystemExit("Missing --server-name for server-info.")
                data = client.server_info(srv)
                if args.field:
                    try:
                        data = select_field(data, args.field)
                    except KeyError as e:
                        logger.error(str(e))
                        return 2
                sys.stdout.write(format_output(data, args.output_format))
            else:
                raise SystemExit(f"Unknown command: {args.command}")
        except requests.HTTPError as e:
            logger.error("HTTP error: %s (%s)", e, getattr(e.response, "text", ""))
            exit_code = 1
        except Exception as e:
            logger.exception("Error: %s", e)
            exit_code = 1

    if args.web or (not args.command and args.web):
        run_web_server(
            default_app_key=args.app_key,
            default_app_secret=args.app_secret,
            default_consumer_key=args.consumer_key,
        )

    return exit_code


# ---------- Web API (Flask) ----------
app = Flask(__name__)


def _get_json_body() -> dict[str, t.Any]:
    """Safely get JSON body as dict, or empty dict."""
    try:
        obj = request.get_json(silent=True)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _get_first(mapping: dict[str, t.Any], keys: list[str]) -> str | None:
    for k in keys:
        if k in mapping and mapping[k] not in (None, ""):
            return str(mapping[k])
    return None


def get_param(name: str, *aliases: str, default: str | None = None) -> str | None:
    """
    Resolve a parameter from: query args > JSON body > form > headers > default.
    Names are case-sensitive for body/form keys, case-insensitive for headers.
    """
    keys = [name, *aliases]

    # Query string
    val = _get_first(request.args, keys)
    if val:
        return val

    # JSON body
    body = _get_json_body()
    val = _get_first(body, keys)
    if val:
        return val

    # Form (application/x-www-form-urlencoded or multipart)
    val = _get_first(request.form, keys)
    if val:
        return val

    # Headers (case-insensitive)
    # Try exact keys, then "X-<Key>" header variants
    for k in keys:
        if k in request.headers:
            v = request.headers.get(k)
            if v not in (None, ""):
                return v
        xk = f"X-{k}".replace("_", "-")
        if xk in request.headers:
            v = request.headers.get(xk)
            if v not in (None, ""):
                return v

    return default


def client_from_request_fallback(
    default_app_key: str | None = None,
    default_app_secret: str | None = None,
    default_consumer_key: str | None = None,
) -> OvhClient:
    """
    Credentials resolution:
    1) Explicit AK/AS/CK from request (query/body/form/headers)
    2) API key gate using WEB_API_KEY (apikey param)
    3) Env/.env (possibly seeded by CLI defaults)
    """
    # 1) Explicit credentials
    q_app_key = get_param("appKey", "applicationKey", "AK", "OVH_APPLICATION_KEY", "App-Key", "Application-Key")
    q_app_secret = get_param("appSecret", "applicationSecret", "AS", "OVH_APPLICATION_SECRET", "App-Secret", "Application-Secret")
    q_consumer_key = get_param("consumerKey", "CK", "OVH_CONSUMER_KEY", "Consumer-Key")

    if q_app_key and q_app_secret:
        return build_client_from_sources(q_app_key, q_app_secret, q_consumer_key, prefer_env=False)

    # 2) apikey gate
    apikey = get_param("apikey", "apiKey", "Api-Key")
    if WEB_API_KEY:
        if not apikey or apikey != WEB_API_KEY:
            abort(Response("Forbidden (invalid or missing apikey)", 403))
    else:
        # If apikey provided while WEB_API_KEY is disabled, forbid to avoid confusion
        if apikey:
            abort(Response("Forbidden (apikey mode disabled by server)", 403))

    # 3) Env/.env
    return build_client_from_sources(default_app_key, default_app_secret, default_consumer_key, prefer_env=True)


def _handle_api_request():
    # Accept params from query/body/form/headers
    output_format = (get_param("output-format", "outputFormat", "format", "Output-Format") or DEFAULT_OUTPUT_FORMAT).lower()
    command = get_param("command", "cmd", "Command")
    server_name = get_param("serverName", "serviceName", "server", "Server-Name", "Service-Name") or DEFAULT_SERVER_NAME
    field = get_param("field", "path", "Field")

    if not command:
        return jsonify({"error": "Missing 'command' parameter"}), 400

    # Build client — let 4xx bubble (e.g., 403 from apikey check)
    try:
        client = client_from_request_fallback()
    except HTTPException:
        raise
    except SystemExit as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Failed to build client")
        return jsonify({"error": str(e)}), 500

    try:
        if command == "list-servers":
            data = client.list_servers()
        elif command == "server-info":
            if not server_name:
                return jsonify({"error": "Missing 'serverName' parameter"}), 400
            data = client.server_info(server_name)
            if field:
                data = select_field(data, field)
        else:
            return jsonify({"error": f"Unknown command: {command}"}), 400

        if output_format == "json":
            return Response(json_compact(data), 200, mimetype="application/json")
        elif output_format == "pretty":
            return Response(json.dumps(data, indent=2, ensure_ascii=False), 200, mimetype="application/json")
        elif output_format == "flat":
            txt = format_output(data, "flat")
            return Response(txt, 200, mimetype="text/plain; charset=utf-8")
        else:
            return jsonify({"error": f"Unknown output-format '{output_format}'"}), 400
    except requests.HTTPError as e:
        text = getattr(e.response, "text", "")
        status = getattr(e.response, "status_code", 500)
        return jsonify({"error": f"HTTP error {status}", "details": text}), int(status or 500)
    except KeyError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        logger.exception("Unhandled error")
        return jsonify({"error": str(e)}), 500


@app.get("/healthz")
def healthz() -> Response:
    return Response("ok\n", 200, mimetype="text/plain")


# Accept both GET and POST for /api
@app.route("/api", methods=["GET", "POST"])
def api_handler():
    return _handle_api_request()


def run_web_server(
    default_app_key: str | None = None,
    default_app_secret: str | None = None,
    default_consumer_key: str | None = None,
) -> None:
    if default_app_key:
        os.environ.setdefault("OVH_APPLICATION_KEY", default_app_key)
    if default_app_secret:
        os.environ.setdefault("OVH_APPLICATION_SECRET", default_app_secret)
    if default_consumer_key:
        os.environ.setdefault("OVH_CONSUMER_KEY", default_consumer_key)

    logger.info("Starting web API on %s:%d", WEB_BIND, WEB_PORT)
    app.run(host=WEB_BIND, port=WEB_PORT)


# ---------- Entrypoint ----------
if __name__ == "__main__":
    sys.exit(cli_main(sys.argv[1:]))
