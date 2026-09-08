"""
===============================================================================
PRODUCTION UPTIME & SSL EXPIRATION MONITOR
===============================================================================
Covered Functionality & Hardening:
1. HTTP 5xx Server Errors Only: Ignores 2xx, 3xx, and 4xx status codes.
2. SSL Handshake/Connection Errors: Catches broken, untrusted, or expired certs.
3. SSL Expiration Window: Alerts STRICTLY when 0 <= days_left <= 14 days.
4. Transient Glitch Retries: 2-attempt retry loop per URL before alerting.
5. Asynchronous Performance: Checks 80+ endpoints concurrently via aiohttp.
6. Rate-Limit Prevention: Bounded by a Semaphore (max 20 concurrent requests).
7. Robust URL Parsing: Uses urllib.parse to handle port numbers and subdomains.
8. Up-to-Date Datetime Utilities: Uses timezone-aware UTC dates (no deprecated APIs).
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


async def send_telegram_summary(alerts_list):
  """Dispatches a consolidated summary of all detected issues to Telegram."""
  if not alerts_list:
    return

  message = "🚨 *UPTIME & SSL ALERT SUMMARY*\n\n" + "\n\n".join(alerts_list)
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
  """Checks the remaining validity days on an SSL certificate."""
  try:
    ssl_context = ssl.create_default_context()
    conn = asyncio.open_connection(domain, port, ssl=ssl_context)
    reader, writer = await asyncio.wait_for(conn, timeout=5)
    cert = writer.get_extra_info("ssl_object").getpeercert()
    writer.close()
    await writer.wait_closed()

    if not cert:
      return

    # Parse SSL certificate expiration date
    expiry_date = datetime.datetime.strptime(
        cert["notAfter"], "%b %d %H:%M:%S %Y %GMT"
    ).replace(tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    days_left = (expiry_date - now).days

    # Alert ONLY if certificate expires strictly within 0 to 14 days
    if 0 <= days_left <= 14:
      alerts.append(f"⚠️ *SSL EXPIRING ({days_left} days left):* `{domain}`")
  except Exception:
    # SSL handshake failures are captured during the primary HTTP request
    pass


async def check_url(session, url, semaphore):
  """Performs asynchronous health checks with 1 retry on failure."""
  async with semaphore:
    parsed_url = urlparse(url)
    domain = parsed_url.hostname
    port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)

    # Retry loop: 2 attempts before flagging down
    for attempt in range(2):
      try:
        async with session.get(
            url, timeout=10, allow_redirects=True
        ) as response:
          # ALERT ONLY ON 5xx HTTP ERRORS
          if response.status >= 500:
            if attempt == 1:
              alerts.append(f"❌ *HTTP {response.status}:* `{url}`")
            else:
              await asyncio.sleep(2)
              continue
          break  # Success (2xx, 3xx, 4xx codes are ignored)
      except aiohttp.ClientSSLError as ssl_err:
        alerts.append(f"🔒 *SSL CERTIFICATE ERROR:* `{url}`\n`{str(ssl_err)}`")
        return
      except Exception as e:
        if attempt == 1:
          alerts.append(f"💥 *DOWN/TIMEOUT:* `{url}`\n`Error: {str(e)}`")
        else:
          await asyncio.sleep(2)
          continue

    # Execute SSL Expiration check if scheme is HTTPS
    if parsed_url.scheme == "https" and domain:
      await check_ssl_expiry(domain, port)


async def main():
  raw_urls = os.environ.get("TARGET_URLS")
  if not raw_urls:
    print("Error: TARGET_URLS secret is missing or empty.")
    return

  try:
    urls = json.loads(raw_urls)
  except json.JSONDecodeError as e:
    print(f"Error parsing TARGET_URLS JSON: {e}")
    return

  semaphore = asyncio.Semaphore(20)  # Max 20 concurrent connections

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
