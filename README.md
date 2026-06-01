# Auto Trade-in Private Note (Crisp Webhook MVP)

Adds one internal Crisp private note per conversation when a visitor sends a message.

The note is built from conversation `meta.data` values injected by your site:

- `trade-in-id`
- `item-id`
- `backoffice-link`

## Behavior

1. Receives Crisp webhook (`message:send`)
2. Ignores non-user messages
3. Fetches conversation from Crisp API
4. Reads `meta.data.backoffice-link` (or derives from trade-in id)
5. Sends private note (`type: note`) into same conversation
6. Stores session in SQLite to avoid duplicate auto-notes

## Requirements

- Python 3.10+
- Crisp token scopes:
  - `website:conversation:messages` (`read` + `write`)
  - `website:conversation:sessions` (`read`)

## Setup

```bash
cp .env.example .env
```

Fill `.env` with real values.

Load env and run:

```bash
set -a
source .env
set +a
python3 app.py
```

Health check:

```bash
curl -i http://localhost:8080/healthz
```

Local webhook simulation (optional):

```bash
python3 simulate_webhook.py --url http://localhost:8080/crisp/webhook --secret "$CRISP_HOOK_SECRET"
```

## Expose locally for Crisp (ngrok)

```bash
ngrok http 8080
```

Use HTTPS URL + webhook path in Crisp plugin settings:

- Endpoint: `https://<ngrok-id>.ngrok-free.app/crisp/webhook`
- Event namespace: `message:send`

If plugin hooks are used, set same hook secret in Crisp + `CRISP_HOOK_SECRET`.

## Expected test

1. Visitor sends message in widget
2. Service receives `message:send`
3. Private note appears in Crisp conversation:
   - format: `Link: <backoffice-link>`
4. Visitor does **not** see note
5. New visitor messages in same session do not create duplicate note

## Railway deploy

- Service root: repository root
- Start command: `python3 app.py`
- Add env vars from `.env.example`
- Set volume mount + `SQLITE_PATH=/data/auto_tradein_note.db`
- Keep 1 replica for strict dedupe

## Config knobs

- `AUTO_NOTE_TEMPLATE` placeholders:
  - `${link}` (alias to backoffice link)
  - `{backoffice_link}` `{trade_in_id}` `{item_id}` `{session_id}` `{website_id}`
- `CRISP_ALLOWED_WEBSITE_IDS` to hard-limit accepted websites
- `SQLITE_PATH` for dedupe persistence location

## Caveats

- Current dedupe = one auto-note per `session_id`
- If both backoffice link and trade-in id are missing in `meta.data`, note is skipped
- Return `500` on Crisp API failure so Crisp can retry webhook delivery
