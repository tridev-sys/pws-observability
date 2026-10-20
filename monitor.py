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
import ssl
from urllib.parse import urlparse
import aiohttp

TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

alerts = []

# Slow-but-healthy pages (and redirect chains) get 30s per attempt, not 10s.
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=30)
MAX_ATTEMPTS = 3
RETRY_DELAY_SECONDS = 5


async def send_telegram_summary(alerts_list):
  """Dispatches a consolidated summary of all detected issues to Telegram."""
  if not alerts_list:
    return

  message = (
      "🚨 *CRITICAL ALERT: ENDPOINT FAILURE DETECTED* 🚨\n\n"
      + "\n\n".join(alerts_list)
  )
  url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
  payload = {
      "chat_id": TELEGRAM_CHAT_ID,
      "text": message,
      "parse_mode": "Markdown",
  }

  async with aiohttp.ClientSession() as session:
    try:
      async with session.post(url, json=payload, timeout=10) as resp:
        if resp.status != 200:
          print(f"Failed to send Telegram message: {await resp.text()}")
    except Exception as e:
      print(f"Telegram API delivery failed: {e}")


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
    writer.close()
    await writer.wait_closed()

    if not cert or "notAfter" not in cert:
      return

    expiry_date = datetime.datetime.strptime(
        cert["notAfter"], "%b %d %H:%M:%S %Y %GMT"
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


def normalize_urls(items):
  """Adds https:// to bare hostnames and drops duplicates, keeping order."""
  seen = set()
  urls = []
  for item in items:
    url = (item.get("url") if isinstance(item, dict) else item) or ""
    url = url.strip()
    if not url:
      continue
    if "://" not in url:
      url = f"https://{url}"
    if url not in seen:
      seen.add(url)
      urls.append(url)
  return urls


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
    tasks = [check_url(session, url, semaphore) for url in urls]
    await asyncio.gather(*tasks)

  if alerts:
    await send_telegram_summary(alerts)
    print(f"Triggered {len(alerts)} alerts to Telegram.")
  else:
    print("All URLs checked successfully. No issues found!")


if __name__ == "__main__":
  asyncio.run(main())
