import os
import uuid
from playwright.async_api import async_playwright

EVIDENCE_DIR = "evidence_store"
if not os.path.exists(EVIDENCE_DIR):
    os.makedirs(EVIDENCE_DIR)

async def capture_web_evidence(target_ip: str, port: int) -> str:
    protocol = "https" if port in [443, 8443] else "http"
    url = f"{protocol}://{target_ip}:{port}"
    filename = f"evidence_{target_ip.replace('.', '_')}_{port}_{uuid.uuid4().hex[:8]}.png"
    filepath = os.path.join(EVIDENCE_DIR, filename)

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()
            
            # ⚡ OPTIMIZATION: 6-second timeout instead of 15 seconds
            await page.goto(url, timeout=6000, wait_until="domcontentloaded")
            await page.screenshot(path=filepath)
            await browser.close()
            
            print(f"[+] Evidence collected for {url}")
            return f"/evidence/{filename}"
            
    except Exception as e:
        print(f"[-] Failed to capture evidence for {url}: {e}")
        return None