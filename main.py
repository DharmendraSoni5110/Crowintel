import os
import sys
import time
import json
import subprocess
import requests

from flask import Flask, request, jsonify, send_file
from zapv2 import ZAPv2

# -------------------------
# PATH SETUP
# -------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# Add BASE_DIR to path so `reports` package is importable
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from reports.generator import generate_report

app = Flask(__name__)

ZAP_PROXY = "http://127.0.0.1:8080"


# -------------------------
# LOGGER
# -------------------------
def log(msg):
    print(f"[+] {msg}", flush=True)


# -------------------------
# ZAP SCAN
# -------------------------
def run_zap(target, findings):
    try:
        log("Connecting to ZAP...")
        zap = ZAPv2(proxies={"http": ZAP_PROXY, "https": ZAP_PROXY})

        log("Starting Spider...")
        scan_id = zap.spider.scan(target)
        # Poll until spider completes (max 60s)
        for _ in range(12):
            progress = int(zap.spider.status(scan_id))
            if progress >= 100:
                break
            time.sleep(5)

        log("Starting Active Scan...")
        ascan_id = zap.ascan.scan(target)
        # Poll until active scan completes (max 120s)
        for _ in range(24):
            progress = int(zap.ascan.status(ascan_id))
            if progress >= 100:
                break
            time.sleep(5)

        alerts = zap.core.alerts()

        for alert in alerts:
            findings.append({
                "tool": "ZAP",
                "severity": alert.get("risk", "Medium"),
                "title": alert.get("alert") or "Unknown Alert",
                "url": alert.get("url", target),
                "description": alert.get("description", ""),
            })

        log(f"ZAP completed: {len(alerts)} findings")

    except Exception as e:
        log(f"[!] ZAP Error: {e}")


# -------------------------
# NUCLEI SCAN
# -------------------------
def run_nuclei(target, findings):
    try:
        log("Running Nuclei...")

        result = subprocess.run(
            ["nuclei", "-u", target, "-json", "-silent"],
            capture_output=True,
            text=True,
            timeout=300,
        )

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                findings.append({
                    "tool": "Nuclei",
                    "severity": info.get("severity", "medium").capitalize(),
                    "title": info.get("name") or data.get("template-id") or "Unknown",
                    "url": data.get("host", target),
                    "description": info.get("description", ""),
                })
            except json.JSONDecodeError:
                continue

        log("Nuclei completed")

    except FileNotFoundError:
        log("[!] Nuclei not found — skipping")
    except subprocess.TimeoutExpired:
        log("[!] Nuclei timed out")
    except Exception as e:
        log(f"[!] Nuclei Error: {e}")


# -------------------------
# NIKTO SCAN
# -------------------------
def run_nikto(target, findings):
    try:
        log("Running Nikto...")

        result = subprocess.run(
            ["nikto", "-h", target, "-Format", "json", "-nointeractive"],
            capture_output=True,
            text=True,
            timeout=300,
        )

        raw = result.stdout.strip()
        if raw:
            try:
                data = json.loads(raw)
                for v in data.get("vulnerabilities", []):
                    msg = v.get("msg", "Unknown")
                    findings.append({
                        "tool": "Nikto",
                        "severity": "Medium",
                        "title": msg,
                        "url": target,
                        "description": msg,
                    })
            except json.JSONDecodeError:
                log("[!] Nikto output was not valid JSON — skipping parse")

        log("Nikto completed")

    except FileNotFoundError:
        log("[!] Nikto not found — skipping")
    except subprocess.TimeoutExpired:
        log("[!] Nikto timed out")
    except Exception as e:
        log(f"[!] Nikto Error: {e}")


# -------------------------
# JWT TEST
# -------------------------
def test_jwt(target, findings):
    try:
        log("Testing JWT None Algorithm...")

        # Unsigned JWT with alg=none
        fake = "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
        r = requests.get(
            target,
            headers={"Authorization": f"Bearer {fake}"},
            timeout=10,
            allow_redirects=True,
        )

        if r.status_code == 200:
            findings.append({
                "tool": "JWT",
                "severity": "High",
                "title": "JWT None Algorithm Accepted",
                "url": target,
                "description": "Server accepts unsigned JWT tokens (alg=none). "
                               "This allows attackers to forge authentication tokens.",
            })
        else:
            log(f"JWT test returned {r.status_code} — likely not vulnerable")

    except requests.RequestException as e:
        log(f"[!] JWT Error: {e}")


# -------------------------
# AUTH TEST
# -------------------------
def test_auth(target, findings):
    try:
        log("Testing Unauthorized Access to admin paths...")

        paths = ["/admin", "/api/admin", "/api/v1/admin", "/dashboard"]

        for p in paths:
            url = target.rstrip("/") + p
            try:
                r = requests.get(url, timeout=10, allow_redirects=False)
                if r.status_code == 200:
                    findings.append({
                        "tool": "Auth",
                        "severity": "High",
                        "title": f"Unauthorized Access — {p}",
                        "url": url,
                        "description": f"Path '{p}' is accessible without authentication "
                                       f"(HTTP 200).",
                    })
            except requests.RequestException:
                continue

    except Exception as e:
        log(f"[!] Auth Error: {e}")


# -------------------------
# SCAN ROUTE
# -------------------------
@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True)

    if not data or "target" not in data:
        return jsonify({"error": "Request body must contain a 'target' field"}), 400

    target = data["target"].strip()
    if not target:
        return jsonify({"error": "Target URL cannot be empty"}), 400

    scan_type = data.get("scan_type", "web")
    findings = []

    log(f"Starting {scan_type} scan: {target}")

    run_zap(target, findings)
    run_nuclei(target, findings)
    run_nikto(target, findings)

    if scan_type == "api":
        test_jwt(target, findings)
        test_auth(target, findings)

    try:
        report_path = generate_report(findings, target)
    except Exception as e:
        log(f"[!] Report generation error: {e}")
        return jsonify({"error": f"Report generation failed: {e}"}), 500

    log(f"Scan completed. Total findings: {len(findings)}")

    return jsonify({
        "status": "completed",
        "total_findings": len(findings),
        "report": report_path,
    })


# -------------------------
# DOWNLOAD REPORT
# -------------------------
@app.route("/download", methods=["GET"])
def download():
    pdf_path = os.path.join(REPORTS_DIR, "report.pdf")
    if not os.path.isfile(pdf_path):
        return jsonify({"error": "Report not found. Run a scan first."}), 404
    return send_file(pdf_path, as_attachment=True, download_name="pentest_report.pdf")


# -------------------------
# HEALTH CHECK
# -------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "running"})


# -------------------------
# ENTRY POINT
# -------------------------
if __name__ == "__main__":
    log("Backend running on http://0.0.0.0:8000")
    app.run(host="0.0.0.0", port=8000, debug=False)
