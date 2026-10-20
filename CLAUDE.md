# CLAUDE.md

Guidance for working in this repo.

## What this repo is

An uptime and SSL-expiry monitor. A GitHub Actions workflow runs `monitor.py`, which checks every URL in the `TARGET_URLS` secret and sends one consolidated Telegram alert when something is wrong. No alert is sent when everything is healthy.

## Files

- `monitor.py`: the whole monitor (async, aiohttp). Entry point is `main()`.
- `.github/workflows/monitor.yml`: the only workflow. Runs on schedule, push to `main`, and `workflow_dispatch`.
- `manifest.json`: machine-readable summary of the configuration. Keep it in sync with the code when values change.
- `scratchpad.md`: investigation notes and open items. Not authoritative for behavior; the code is.
- `README.md`: one line. Not the source of truth.

## Secrets (names only)

- `TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID`: Telegram bot credentials.
- `TARGET_URLS`: JSON array. Each item is a string or `{"url": "..."}`.

Never print or commit secret values. A stale hostname in `TARGET_URLS` causes a permanent DNS-failure alert, so check the list when an alert names a host you no longer use.

## Alert rules (intentional, keep them)

- Only HTTP 5xx counts as an HTTP failure. 2xx, 3xx, and 4xx never alert.
- A 5xx or connection/timeout error alerts only after all attempts fail.
- SSL certificate errors alert immediately, with no retry.
- SSL expiry alerts when `0 <= days_left <= 14`. Expired certificates do not produce this alert; they show up as an SSL certificate error.
- Retry settings live in `monitor.py` as constants: `REQUEST_TIMEOUT` (30s total), `MAX_ATTEMPTS` (3), `RETRY_DELAY_SECONDS` (5).

## Monitoring window

The workflow's first step checks the IST hour and skips every later step outside the window. The window applies to every trigger. Bounds are `MONITOR_START_HOUR_IST` and `MONITOR_END_HOUR_IST` in `monitor.yml`. GitHub cron is always UTC, so the cron expression and the IST window are set separately.

## Conventions

- Match `monitor.py`'s style: 2-space indentation, docstrings on functions, comments that explain why.
- Commit messages use the repo's existing short style, with a `Co-Authored-By` trailer when Claude writes the change.
- Do not push to `main` from a session. Work on a branch and open a PR.

## Testing

There is no test suite. To check behavior, run `check_url` against a local aiohttp test server. Cover: slow page, redirect, 404, 503, and a refused connection. Validate workflow YAML with `yaml.safe_load`.

## Known open items

- The `workflow_dispatch` runs that fire every 10 minutes are triggered by the `tridev-sys` account, from outside this repo. Find and disable that external dispatcher.
- `TARGET_URLS` still needs `xlsx-builder.koala.cx` replaced with `xlsx-builder.heykoala.ai`.
- Telegram alerts repeat every run while an endpoint stays down. There is no dedup, no 4096-character length guard, and the legacy `Markdown` parse mode is used.
