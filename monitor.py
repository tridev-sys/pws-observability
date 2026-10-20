"""
===============================================================================
PRODUCTION UPTIME & SSL EXPIRATION MONITOR (HIGH PRIORITY SIREN)
===============================================================================
Covered Functionality:
1. Universal High-Priority Formatting: Formats every alert as a Critical Siren.
2. HTTP 5xx Server Errors Only: Ignores 2xx, 3xx, and 4xx status codes.
3. SSL Expiration Window: Alerts STRICTLY when 0 <= days_left <= 14 days.
4. SSL Connection Failures: Catches broken, untrusted, or expired certs.
5. SNI Support: Sends server_hostname to resolve multi-tenant/CDN SSL certs correctly.
6. Transient Glitch Retries: 3 attempts (30s timeout each) before alerting.
7. Safe Bounded Concurrency: Uses Semaphore(20) to prevent WAF throttling.
===============================================================================
"""

import asyncio
import datetime
import json
import os
import re
import ssl
import sys
import time
from urllib.parse import urlparse
import aiohttp

TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

alerts = []

# Slow-but-healthy pages (and redirect chains) get 30s per attempt, not 10s.
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=30)
MAX_ATTEMPTS = 3
RETRY_DELAY_SECONDS = 5


TELEGRAM_HEADER = "🚨 *CRITICAL ALERT: ENDPOINT FAILURE DETECTED* 🚨\n\n"
# Telegram rejects messages over 4096 characters; keep headroom for the header.
TELEGRAM_MAX_CHARS = 4000
MAX_ALERT_CHARS = 1000

# Repeat alerts for the same problem are suppressed for this long (kept short on purpose).
ALERT_STATE_PATH = os.environ.get("ALERT_STATE_PATH", "alert_state.json")
ALERT_COOLDOWN_SECONDS = int(os.environ.get("ALERT_COOLDOWN_MINUTES", "15")) * 60


def chunk_alerts(alerts_list):
  """Groups alerts into message bodies that each fit Telegram's length limit."""
  chunks = []
  current = ""
  for alert in alerts_list:
    alert = alert[:MAX_ALERT_CHARS]
    candidate = f"{current}\n\n{alert}" if current else alert
    if current and len(candidate) > TELEGRAM_MAX_CHARS:
      chunks.append(current)
      current = alert
    else:
      current = candidate
  if current:
    chunks.append(current)
  return chunks


async def post_telegram_message(session, text):
  """Sends one message. Retries once as plain text if Markdown parsing fails."""
  if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
    print("Telegram credentials missing: TELEGRAM_TOKEN or TELEGRAM_CHAT_ID.")
    return False

  url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
  for parse_mode in ("Markdown", None):
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text}
    if parse_mode:
      payload["parse_mode"] = parse_mode
    try:
      async with session.post(url, json=payload, timeout=10) as resp:
        if resp.status == 200:
          return True
        print(f"Telegram rejected message (HTTP {resp.status}): {await resp.text()}")
        if resp.status != 400:
          return False
    except Exception as e:
      print(f"Telegram API delivery failed: {e}")
      return False
  return False


async def send_telegram_summary(alerts_list):
  """Sends all alerts in length-safe messages. Returns True only if all were delivered."""
  if not alerts_list:
    return True

  delivered = True
  async with aiohttp.ClientSession() as session:
    for chunk in chunk_alerts(alerts_list):
      if not await post_telegram_message(session, TELEGRAM_HEADER + chunk):
        delivered = False
  return delivered


async def check_ssl_expiry(domain, port=443):
  """Checks the remaining validity days on an SSL certificate using SNI."""
  try:
    ssl_context = ssl.create_default_context()
    # Explicitly pass server_hostname for proper SNI resolution on multi-tenant/CDN hosts
    conn = asyncio.open_connection(
        domain, port, ssl=ssl_context, server_hostname=domain
    )
    reader, writer = await asyncio.wait_for(conn, timeout=5)
    cert = writer.get_extra_info("ssl_object").getpeercert()
    # Abort instead of a graceful close: some servers send data after close_notify,
    # which makes a graceful shutdown raise even though the certificate was read.
    writer.transport.abort()

    if not cert or "notAfter" not in cert:
      return

    # OpenSSL pads single-digit days with a space ("Jan  8"); collapse it first.
    not_after = " ".join(cert["notAfter"].split())
    expiry_date = datetime.datetime.strptime(
        not_after, "%b %d %H:%M:%S %Y %Z"
    ).replace(tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    days_left = (expiry_date - now).days

    if 0 <= days_left <= 14:
      alerts.append(
          f"🚨 *SSL EXPIRING CRITICAL ({days_left} days left):* `{domain}`"
      )
  except Exception as e:
    # Print diagnostic info to GitHub Actions logs without breaking execution
    print(f"SSL Expiry check skipped for {domain}:{port} -> {e}")


async def check_url(session, url, semaphore):
  """Alerts only if every attempt fails with a 5xx or a connection error."""
  async with semaphore:
    url = url.get("url") if isinstance(url, dict) else url

    parsed_url = urlparse(url)
    domain = parsed_url.hostname
    port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)

    failure = None
    for attempt in range(MAX_ATTEMPTS):
      try:
        async with session.get(
            url, timeout=REQUEST_TIMEOUT, allow_redirects=True
        ) as response:
          if response.status < 500:
            failure = None
            break
          failure = f"🚨 *HTTP {response.status} FAILURE:* `{url}`"
      except aiohttp.ClientSSLError as ssl_err:
        alerts.append(f"🚨 *SSL CERTIFICATE ERROR:* `{url}`\n`{str(ssl_err)}`")
        return
      except Exception as e:
        # Timeouts have an empty message, so fall back to the exception type.
        detail = str(e) or type(e).__name__
        failure = f"🚨 *ENDPOINT DOWN/TIMEOUT:* `{url}`\n`Error: {detail}`"

      if attempt < MAX_ATTEMPTS - 1:
        await asyncio.sleep(RETRY_DELAY_SECONDS)

    if failure:
      alerts.append(failure)

    if parsed_url.scheme == "https" and domain:
      await check_ssl_expiry(domain, port)


async def safe_check_url(session, url, semaphore):
  """Runs one check, turning any unexpected error into an alert instead of aborting the run."""
  try:
    await check_url(session, url, semaphore)
  except Exception as e:
    alerts.append(f"🚨 *CHECK ERROR:* `{url}`\n`{type(e).__name__}: {e}`")


def normalize_urls(items):
  """Adds https:// to bare hostnames and drops duplicates, keeping order."""
  seen = set()
  urls = []
  for item in items:
    raw = item.get("url") if isinstance(item, dict) else item
    url = str(raw or "").strip()
    if not url:
      continue
    if "://" not in url:
      url = f"https://{url}"
    if url not in seen:
      seen.add(url)
      urls.append(url)
  return urls


def alert_key(alert):
  """Stable identity for an alert: its first line, without the changing day count."""
  return re.sub(r"\d+ days left", "", alert.splitlines()[0])


def load_state():
  try:
    with open(ALERT_STATE_PATH) as f:
      return json.load(f)
  except (OSError, json.JSONDecodeError):
    return {}


def save_state(state):
  with open(ALERT_STATE_PATH, "w") as f:
    json.dump(state, f)


async def main():
  raw_urls = os.environ.get("TARGET_URLS")
  if not raw_urls:
    print("Error: TARGET_URLS secret is empty.")
    return

  try:
    urls = normalize_urls(json.loads(raw_urls))
  except json.JSONDecodeError as e:
    print(f"Error parsing TARGET_URLS JSON: {e}")
    return

  semaphore = asyncio.Semaphore(20)

  async with aiohttp.ClientSession() as session:
    tasks = [safe_check_url(session, url, semaphore) for url in urls]
    await asyncio.gather(*tasks)

  state = load_state()
  now = time.time()
  # Drop state for problems that are no longer failing, so a relapse alerts at once.
  active = {alert_key(a) for a in alerts}
  state = {k: v for k, v in state.items() if k in active}

  if not alerts:
    save_state(state)
    print("All URLs checked successfully. No issues found!")
    return

  to_send = [a for a in alerts if now - state.get(alert_key(a), 0) >= ALERT_COOLDOWN_SECONDS]
  delivered = True
  if to_send:
    delivered = await send_telegram_summary(to_send)
    print(f"Sent {len(to_send)} alerts to Telegram (delivered={delivered}).")
    if delivered:
      state.update({alert_key(a): now for a in to_send})
  else:
    print(f"{len(alerts)} active alerts were already sent within the cooldown.")

  save_state(state)
  if not delivered:
    sys.exit(1)  # Fail the run so a lost alert is visible in Actions.


if __name__ == "__main__":
  asyncio.run(main())
