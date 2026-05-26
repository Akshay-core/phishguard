"""
PhishGuard — Dataset Download Script
======================================
Downloads phishing and legitimate URL datasets for training.

Sources:
  Phishing: PhishTank (verified phishing URLs, free)
  Legitimate: Tranco top-1M list (academic, CC-BY 4.0)

Usage:
  python download_datasets.py

Outputs:
  datasets/phishing_phishtank.csv   — verified phishing URLs
  datasets/legit_tranco.csv         — top legitimate domains

Author: Akshay | https://akshay.fruvvi.com
"""

import csv
import io
import json
import logging
import zipfile
from pathlib import Path

import requests
from tqdm import tqdm

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("PhishGuard.download")

DATASETS_DIR = Path(__file__).parent.parent / "datasets"
DATASETS_DIR.mkdir(parents=True, exist_ok=True)

# ─── PhishTank ────────────────────────────────────────────────────────────────

PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.json.bz2"

def download_phishtank() -> None:
    """
    Download verified phishing URLs from PhishTank.
    Free for non-commercial use. Register at phishtank.com for higher rate limits.
    No API key needed for basic JSON dump.
    """
    output_path = DATASETS_DIR / "phishing_phishtank.csv"

    log.info("Downloading PhishTank dataset...")
    log.info("Source: http://data.phishtank.com/")

    try:
        response = requests.get(
            "http://data.phishtank.com/data/online-valid.json",
            timeout=60,
            stream=True,
            headers={"User-Agent": "PhishGuard Research/1.0 (akshay.fruvvi.com)"},
        )
        response.raise_for_status()

        data = response.json()
        urls = [entry["url"] for entry in data if entry.get("verified") == "yes"]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["url", "label"])
            for url in urls:
                writer.writerow([url, 1])

        log.info(f"PhishTank: {len(urls)} verified phishing URLs → {output_path}")

    except Exception as e:
        log.warning(f"PhishTank download failed: {e}")
        log.info("Creating sample phishing dataset for testing...")
        _create_sample_phishing_dataset(output_path)


# ─── Tranco (Legitimate) ─────────────────────────────────────────────────────

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

def download_tranco(limit: int = 50_000) -> None:
    """
    Download Tranco top-1M list and convert top N to URLs.
    Tranco is a research-grade list that resists manipulation.
    https://tranco-list.eu/
    """
    output_path = DATASETS_DIR / "legit_tranco.csv"

    log.info(f"Downloading Tranco top-{limit:,} legitimate domains...")

    try:
        response = requests.get(TRANCO_URL, timeout=120, stream=True)
        response.raise_for_status()

        total_size = int(response.headers.get("content-length", 0))
        content = b""
        with tqdm(total=total_size, unit="B", unit_scale=True, desc="Tranco") as pbar:
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                pbar.update(len(chunk))

        with zipfile.ZipFile(io.BytesIO(content)) as z:
            csv_name = [n for n in z.namelist() if n.endswith(".csv")][0]
            with z.open(csv_name) as f:
                reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
                rows = [row for _, row in zip(range(limit), reader) if len(row) >= 2]

        domains = [row[1].strip() for row in rows if row[1].strip()]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["url", "label"])
            for domain in domains:
                writer.writerow([f"https://{domain}", 0])

        log.info(f"Tranco: {len(domains)} legitimate URLs → {output_path}")

    except Exception as e:
        log.warning(f"Tranco download failed: {e}")
        log.info("Creating sample legitimate dataset for testing...")
        _create_sample_legit_dataset(output_path)


# ─── Sample datasets (fallback) ───────────────────────────────────────────────

def _create_sample_phishing_dataset(path: Path) -> None:
    """Minimal sample phishing dataset for offline testing."""
    phishing_urls = [
        "http://paypa1-security-alert.xyz/login",
        "http://192.168.1.1/account/verify",
        "http://apple-id.account-suspended.tk/signin",
        "https://secure-bankofamerica-login.click/verify",
        "http://amazon-account.gq/update-payment",
        "https://login.microsoftonline.account-verify.xyz/auth",
        "http://paypal.com.account-alert.pw/confirm",
        "https://netflix-billing-error.click/update",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        for url in phishing_urls:
            writer.writerow([url, 1])
    log.info(f"Sample phishing dataset created: {path}")


def _create_sample_legit_dataset(path: Path) -> None:
    """Minimal sample legitimate dataset for offline testing."""
    legit_urls = [
        "https://google.com",
        "https://github.com",
        "https://stackoverflow.com",
        "https://mozilla.org",
        "https://wikipedia.org",
        "https://amazon.com",
        "https://apple.com",
        "https://microsoft.com",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        for url in legit_urls:
            writer.writerow([url, 0])
    log.info(f"Sample legitimate dataset created: {path}")


# ─── Entrypoint ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info("PhishGuard — Dataset Download")
    log.info("=" * 50)
    download_phishtank()
    download_tranco(limit=50_000)
    log.info("\n✓ Datasets ready in: ml/datasets/")
    log.info("  Next step: python training/train.py")
