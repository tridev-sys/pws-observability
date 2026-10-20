# Scratchpad: monitor false positives and night-time runs

Working notes from the investigation. The code is the source of truth; these notes record why decisions were made.

## Issue 1: false-positive Telegram alerts

**Symptom:** Alerts such as `ENDPOINT DOWN/TIMEOUT` with an empty `Error:` for sites that are up.

**Root cause:** Only the exception branch alerts on non-5xx problems. It used a 10s timeout and 2 attempts 2s apart. Slow pages and redirect chains exceed 10s, and `str(TimeoutError())` is empty.

**Reproduction (local, aiohttp test server):**
- Redirect to a page that takes 12s → alert after about 24s, empty error. Matches the production signature.

**Fix applied:**
- `REQUEST_TIMEOUT` 30s, `MAX_ATTEMPTS` 3, `RETRY_DELAY_SECONDS` 5.
- Alert only when every attempt fails.
- Error text falls back to the exception type.

**Verification:**
- Slow redirect → no alert (12.1s).
- 404 → no alert.
- 503 → alert.
- Refused connection → alert with the real message.

## Issue 2: monitor running 24x7

**Expected:** Quiet at night, start again early morning.

**Findings:**
- Cron was `*/10 6-23 * * *` in UTC, so it already skipped 00:00–05:59 UTC. That is 05:30–11:30 IST, which is the wrong window for an IST owner.
- Run history (last ~200 runs): `workflow_dispatch` accounted for almost all runs, triggered by `tridev-sys`. Every 10 minutes from 06:00 to 23:50 UTC.
- `schedule` runs were sparse (10 in two days). Two fired outside the window (00:42 and 21:44 UTC).
- No dispatching script exists in this repo. Local `crontab` and launchd show nothing relevant.

**Fix applied:**
- Window step at the top of the job, using IST hours 06:00–23:00.
- Every later step gated on the window output.
- Cron narrowed to `*/10 0-17 * * *` UTC (05:30–23:20 IST).

**Open:** Find and disable the external dispatcher. Without that, runs continue but exit early.

## Issue 3: stale target host

- `xlsx-builder.koala.cx` does not resolve (DNS failure). This is what produced the "Name or service not known" alert.
- The live host is `xlsx-builder.heykoala.ai` (HTTP 404 on root, responds in about 0.6s).
- Fix is in the `TARGET_URLS` secret, which is not readable from this repo.

## Other observations (not addressed)

- No dedup. A down endpoint re-alerts every run.
- No 4096-character guard. A large batch of alerts can be rejected by Telegram, and the failure is only logged.
- Legacy `Markdown` parse mode. Raw exception text inside backticks can break parsing.

## Open questions

- Confirm the IST window (06:00–23:00). Change `MONITOR_START_HOUR_IST` and `MONITOR_END_HOUR_IST` in `monitor.yml` if needed.
- Which account or system owns the 10-minute dispatch loop?
