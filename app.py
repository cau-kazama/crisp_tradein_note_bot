#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib import error, parse, request


DEFAULT_BASE_URL = "https://api.crisp.chat/v1"


class CrispApiError(RuntimeError):
    pass


class SignatureError(RuntimeError):
    pass


@dataclass(frozen=True)
class Config:
    host: str
    port: int
    webhook_path: str
    health_path: str
    crisp_identifier: str
    crisp_key: str
    crisp_base_url: str
    crisp_hook_secret: str
    max_signature_skew_seconds: int
    allowed_website_ids: set[str]
    note_template: str
    note_marker: str
    sqlite_path: str


class CrispApiClient:
    def __init__(self, identifier: str, key: str, base_url: str):
        self.base_url = base_url.rstrip("/")
        token = f"{identifier}:{key}".encode("utf-8")
        self.auth = base64.b64encode(token).decode("ascii")

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        url = f"{self.base_url}/{path.lstrip('/')}"
        headers = {
            "Authorization": f"Basic {self.auth}",
            "X-Crisp-Tier": "plugin",
            "Accept": "application/json",
            "User-Agent": "doji-auto-tradein-note/1.0",
        }

        payload = None
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = request.Request(url=url, method=method.upper(), headers=headers, data=payload)

        try:
            with request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                parsed = json.loads(raw) if raw else {}
                return parsed.get("data", parsed)
        except error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            raise CrispApiError(f"HTTP {exc.code} {method} {url}: {raw[:800]}") from exc
        except error.URLError as exc:
            raise CrispApiError(f"Network error {method} {url}: {exc.reason}") from exc

    def get_conversation(self, website_id: str, session_id: str) -> dict[str, Any]:
        data = self._request(
            "GET",
            f"/website/{parse.quote(website_id)}/conversation/{parse.quote(session_id)}",
        )
        if not isinstance(data, dict):
            raise CrispApiError("Unexpected conversation payload format")
        return data

    def send_private_note(self, website_id: str, session_id: str, content: str) -> dict[str, Any]:
        data = self._request(
            "POST",
            f"/website/{parse.quote(website_id)}/conversation/{parse.quote(session_id)}/message",
            body={
                "type": "note",
                "from": "operator",
                "origin": "chat",
                "content": content,
            },
        )
        if not isinstance(data, dict):
            return {"raw": data}
        return data


class DedupStore:
    def __init__(self, sqlite_path: str):
        self.sqlite_path = sqlite_path
        self.lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.sqlite_path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS session_notes (
                  session_id TEXT PRIMARY KEY,
                  website_id TEXT NOT NULL,
                  trade_in_id TEXT,
                  note_content TEXT NOT NULL,
                  sent_fingerprint TEXT,
                  sent_at_ms INTEGER NOT NULL
                )
                """
            )
            conn.commit()

    def has_session_note(self, session_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM session_notes WHERE session_id = ? LIMIT 1",
                (session_id,),
            ).fetchone()
        return row is not None

    def save_session_note(
        self,
        *,
        session_id: str,
        website_id: str,
        trade_in_id: str | None,
        note_content: str,
        sent_fingerprint: str | None,
    ) -> None:
        now_ms = int(time.time() * 1000)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO session_notes (
                  session_id, website_id, trade_in_id, note_content, sent_fingerprint, sent_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (session_id, website_id, trade_in_id, note_content, sent_fingerprint, now_ms),
            )
            conn.commit()


class AutoTradeInNoteService:
    def __init__(self, config: Config):
        self.config = config
        self.api = CrispApiClient(config.crisp_identifier, config.crisp_key, config.crisp_base_url)
        self.store = DedupStore(config.sqlite_path)
        self.processing_lock = threading.Lock()
        self.in_flight_sessions: set[str] = set()

    def verify_signature(self, raw_body: str, headers: dict[str, str]) -> None:
        secret = self.config.crisp_hook_secret.strip()
        if not secret:
            return

        ts_raw = headers.get("x-crisp-request-timestamp", "").strip()
        sig_raw = headers.get("x-crisp-signature", "").strip()

        if not ts_raw or not sig_raw:
            raise SignatureError("Missing Crisp signature headers")

        try:
            ts_int = int(ts_raw)
        except ValueError as exc:
            raise SignatureError("Invalid X-Crisp-Request-Timestamp header") from exc

        # Accept both seconds and milliseconds.
        ts_seconds = ts_int / 1000 if ts_int > 10_000_000_000 else ts_int
        now = int(time.time())
        if abs(now - ts_seconds) > self.config.max_signature_skew_seconds:
            raise SignatureError("Stale Crisp webhook timestamp")

        message = f"[{ts_raw};{raw_body}]".encode("utf-8")
        digest = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()

        valid_values = {
            digest,
            digest.lower(),
            f"sha256={digest}",
            f"sha256={digest.lower()}",
        }
        incoming = sig_raw.strip()

        ok = any(hmac.compare_digest(incoming, candidate) for candidate in valid_values)
        if not ok:
            raise SignatureError("Invalid Crisp webhook signature")

    def _extract_tradein_fields(self, conversation: dict[str, Any]) -> dict[str, str | None]:
        meta = conversation.get("meta") if isinstance(conversation.get("meta"), dict) else {}
        data = meta.get("data") if isinstance(meta.get("data"), dict) else {}

        trade_in_id = data.get("trade-in-id") or data.get("tradeInId") or data.get("tradeinId")
        item_id = data.get("item-id") or data.get("itemId")
        backoffice_link = data.get("backoffice-link") or data.get("backofficeLink")

        if not trade_in_id and isinstance(backoffice_link, str):
            parsed = parse.urlparse(backoffice_link)
            chunks = [part for part in parsed.path.split("/") if part]
            if len(chunks) >= 2 and chunks[-2] == "trade-ins":
                trade_in_id = chunks[-1]

        if not backoffice_link and trade_in_id:
            backoffice_link = f"https://admin.tradein.doji.com.br/trade-ins/{trade_in_id}"

        return {
            "trade_in_id": trade_in_id,
            "item_id": item_id,
            "backoffice_link": backoffice_link,
        }

    def _build_note(self, fields: dict[str, str | None], session_id: str, website_id: str) -> str:
        values = {
            "trade_in_id": fields.get("trade_in_id") or "",
            "item_id": fields.get("item_id") or "",
            "backoffice_link": fields.get("backoffice_link") or "",
            "session_id": session_id,
            "website_id": website_id,
            "link": fields.get("backoffice_link") or "",
        }

        text = self.config.note_template
        for key, value in values.items():
            text = text.replace(f"${{{key}}}", str(value))

        class _SafeDict(dict):
            def __missing__(self, key: str) -> str:
                return ""

        text = text.format_map(_SafeDict(values)).strip()

        if not text:
            raise ValueError("Generated note text is empty")

        return text

    def process_webhook(self, payload: dict[str, Any], raw_body: str, headers: dict[str, str]) -> dict[str, Any]:
        self.verify_signature(raw_body, headers)

        event = str(payload.get("event") or "")
        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}

        if event != "message:send":
            return {"ok": True, "status": "ignored", "reason": f"unsupported_event:{event}"}

        from_actor = str(data.get("from") or "").lower()
        if from_actor != "user":
            return {"ok": True, "status": "ignored", "reason": f"from:{from_actor or 'unknown'}"}

        session_id = str(data.get("session_id") or "").strip()
        website_id = str(payload.get("website_id") or data.get("website_id") or "").strip()

        if not session_id or not website_id:
            return {"ok": True, "status": "ignored", "reason": "missing_session_or_website"}

        if self.config.allowed_website_ids and website_id not in self.config.allowed_website_ids:
            return {"ok": True, "status": "ignored", "reason": "website_not_allowed", "website_id": website_id}

        with self.processing_lock:
            if session_id in self.in_flight_sessions:
                return {"ok": True, "status": "ignored", "reason": "session_in_flight", "session_id": session_id}
            self.in_flight_sessions.add(session_id)

        try:
            if self.store.has_session_note(session_id):
                return {"ok": True, "status": "ignored", "reason": "already_noted", "session_id": session_id}

            conversation = self.api.get_conversation(website_id, session_id)
            fields = self._extract_tradein_fields(conversation)
            if not fields.get("backoffice_link"):
                return {
                    "ok": True,
                    "status": "ignored",
                    "reason": "backoffice_link_missing",
                    "session_id": session_id,
                }

            note_text = self._build_note(fields, session_id, website_id)
            sent = self.api.send_private_note(website_id, session_id, note_text)

            self.store.save_session_note(
                session_id=session_id,
                website_id=website_id,
                trade_in_id=fields.get("trade_in_id"),
                note_content=note_text,
                sent_fingerprint=(sent.get("fingerprint") if isinstance(sent, dict) else None),
            )

            return {
                "ok": True,
                "status": "sent",
                "website_id": website_id,
                "session_id": session_id,
                "trade_in_id": fields.get("trade_in_id"),
                "item_id": fields.get("item_id"),
                "backoffice_link": fields.get("backoffice_link"),
                "note_preview": note_text[:160],
            }
        finally:
            with self.processing_lock:
                self.in_flight_sessions.discard(session_id)


def load_config() -> Config:
    identifier = os.environ.get("CRISP_IDENTIFIER", "").strip()
    key = os.environ.get("CRISP_KEY", "").strip()
    if not identifier or not key:
        raise SystemExit("Set CRISP_IDENTIFIER and CRISP_KEY.")

    website_ids_raw = os.environ.get("CRISP_ALLOWED_WEBSITE_IDS", "").strip()
    allowed = {x.strip() for x in website_ids_raw.split(",") if x.strip()} if website_ids_raw else set()

    webhook_path = os.environ.get("WEBHOOK_PATH", "/crisp/webhook").strip() or "/crisp/webhook"
    if not webhook_path.startswith("/"):
        webhook_path = "/" + webhook_path

    health_path = os.environ.get("HEALTH_PATH", "/healthz").strip() or "/healthz"
    if not health_path.startswith("/"):
        health_path = "/" + health_path

    return Config(
        host=os.environ.get("HOST", "0.0.0.0").strip() or "0.0.0.0",
        port=int(os.environ.get("PORT", "8080")),
        webhook_path=webhook_path,
        health_path=health_path,
        crisp_identifier=identifier,
        crisp_key=key,
        crisp_base_url=os.environ.get("CRISP_BASE_URL", DEFAULT_BASE_URL).strip() or DEFAULT_BASE_URL,
        crisp_hook_secret=os.environ.get("CRISP_HOOK_SECRET", "").strip(),
        max_signature_skew_seconds=int(os.environ.get("CRISP_HOOK_MAX_SKEW_SECONDS", "300")),
        allowed_website_ids=allowed,
        note_template=os.environ.get(
            "AUTO_NOTE_TEMPLATE",
            "Link: ${link}",
        ),
        note_marker=os.environ.get("AUTO_NOTE_MARKER", "[AUTO_TRADEIN_NOTE]").strip(),
        sqlite_path=os.environ.get("SQLITE_PATH", "./auto_tradein_note.db").strip() or "./auto_tradein_note.db",
    )


def build_handler(service: AutoTradeInNoteService, config: Config):
    class Handler(BaseHTTPRequestHandler):
        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args: Any) -> None:
            logging.info("%s - %s", self.address_string(), format % args)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == config.health_path:
                self._send_json(HTTPStatus.OK, {"ok": True, "service": "auto-tradein-note"})
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path != config.webhook_path:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})
                return

            content_length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(content_length) if content_length > 0 else b""
            raw_text = raw.decode("utf-8", errors="replace")

            try:
                payload = json.loads(raw_text) if raw_text else {}
                if not isinstance(payload, dict):
                    self._send_json(HTTPStatus.OK, {"ok": True, "status": "ignored", "reason": "non_object_payload"})
                    return

                headers = {k.lower(): v for k, v in self.headers.items()}
                result = service.process_webhook(payload, raw_text, headers)
                self._send_json(HTTPStatus.OK, result)
            except SignatureError as exc:
                logging.warning("Rejected webhook: %s", exc)
                self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": str(exc)})
            except CrispApiError as exc:
                logging.exception("Crisp API error while processing webhook")
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": str(exc)})
            except Exception as exc:  # noqa: BLE001
                logging.exception("Unhandled webhook processing error")
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": str(exc)})

    return Handler


def main() -> None:
    logging.basicConfig(
        level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    config = load_config()
    service = AutoTradeInNoteService(config)

    handler = build_handler(service, config)
    server = ThreadingHTTPServer((config.host, config.port), handler)

    logging.info("Auto trade-in note service listening on %s:%s", config.host, config.port)
    logging.info("Webhook path: %s | Health path: %s", config.webhook_path, config.health_path)
    logging.info("Allowed website IDs: %s", sorted(config.allowed_website_ids) if config.allowed_website_ids else "ALL")
    logging.info("Using signature verification: %s", bool(config.crisp_hook_secret))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
