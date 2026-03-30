import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

# Resolve paths relative to this file — works regardless of CWD
_HERE           = os.path.abspath(os.path.dirname(__file__))
TEMPLATE_PATH   = os.path.join(_HERE, "template.html")
REPORT_HTML_PATH = os.path.join(_HERE, "report.html")
REPORT_PDF_PATH  = os.path.join(_HERE, "report.pdf")


# -------------------------
# DEDUPLICATE FINDINGS
# -------------------------
def deduplicate_findings(findings):
    """
    Collapse duplicate findings that share the same title + url.
    Keeps the first occurrence and discards exact duplicates.
    """
    seen = set()
    unique = []
    for f in findings:
        key = (
            (f.get("title") or "").strip().lower(),
            (f.get("url")   or "").strip().lower(),
        )
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# -------------------------
# GROUP FINDINGS
# -------------------------
def group_findings(findings):
    groups = {
        "A. Web Security":      [],
        "B. Infrastructure":    [],
        "C. Domain Reputation": [],
        "D. DNS & Email":       [],
        "E. Advanced":          [],
    }

    for f in findings:
        title = f.get("title") or ""
        if any(k in title for k in ("TLS", "Header", "CSP", "HSTS", "Cache",
                                     "Version", "Cross-Domain", "Modern Web",
                                     "Timestamp", "Cookie", "XSS", "Frame")):
            groups["A. Web Security"].append(f)
        elif any(k in title for k in ("Port", "IP", "Service", "Open", "Firewall")):
            groups["B. Infrastructure"].append(f)
        elif any(k in title for k in ("Domain", "Reputation", "Blacklist", "WHOIS")):
            groups["C. Domain Reputation"].append(f)
        elif any(k in title for k in ("DNS", "Email", "SPF", "DMARC", "MX", "SMTP")):
            groups["D. DNS & Email"].append(f)
        else:
            groups["E. Advanced"].append(f)

    # Remove empty groups
    return {k: v for k, v in groups.items() if v}


# -------------------------
# CALCULATE SCORES
# -------------------------
def calculate_scores(findings):
    """
    Score each finding:
      Low      → 10  (pass)
      Medium   →  5  (warn)
      High     →  0  (fail)
      Critical →  0  (fail)

    Returns (score_list, total_score, max_possible_score).
    """
    scores = []
    total = 0

    for f in findings:
        sev = (f.get("severity") or "Medium").strip().capitalize()
        if sev == "Low":
            s = 10
        elif sev == "Medium":
            s = 5
        else:
            s = 0

        scores.append({"name": f.get("title") or "Unknown", "score": s})
        total += s

    max_possible = len(findings) * 10 if findings else 1
    return scores, total, max_possible


# -------------------------
# GENERATE REPORT
# -------------------------
def generate_report(findings, target):
    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Deduplicate before processing
    findings = deduplicate_findings(findings)

    # Normalize severity capitalization
    for f in findings:
        if f.get("severity"):
            f["severity"] = f["severity"].strip().capitalize()

    pass_count = sum(1 for f in findings if f.get("severity") == "Low")
    warn_count = sum(1 for f in findings if f.get("severity") == "Medium")
    fail_count = sum(1 for f in findings if f.get("severity") in ("High", "Critical"))

    scores, total_score, max_score = calculate_scores(findings)

    # Decision: approved when ≥ 70 % of max possible score
    score_pct = round((total_score / max_score * 100), 1) if max_score > 0 else 0.0
    decision  = "Approved" if score_pct >= 70 else "Rejected"
    risk      = (
        "Critical Risk" if fail_count > 5
        else "High Risk" if fail_count > 2
        else "Moderate Risk" if fail_count > 0 or warn_count > 5
        else "Low Risk"
    )

    grouped = group_findings(findings)

    if not os.path.isfile(TEMPLATE_PATH):
        raise FileNotFoundError(f"Template not found: {TEMPLATE_PATH}")

    env      = Environment(loader=FileSystemLoader(os.path.dirname(TEMPLATE_PATH)))
    template = env.get_template(os.path.basename(TEMPLATE_PATH))

    html = template.render(
        target       = target,
        date         = date,
        pass_count   = pass_count,
        warn_count   = warn_count,
        fail_count   = fail_count,
        score        = total_score,
        max_score    = max_score,
        score_pct    = score_pct,
        decision     = decision,
        risk         = risk,
        grouped_findings = grouped,
        compliance   = [],
        scores       = scores,
        conditions   = [
            "Remediate all High and Critical severity findings before go-live",
            "Enable Web Application Firewall (WAF) in blocking mode",
            "Enforce HSTS, CSP, and all missing security headers across every endpoint",
            "Fix JWT algorithm vulnerability and rotate all signing secrets",
            "Restrict or remove unauthenticated access to admin endpoints",
        ],
        recommendations = [
            "Implement missing HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)",
            "Resolve JWT None Algorithm vulnerability immediately — rotate all secrets",
            "Restrict admin and sensitive endpoints behind authentication middleware",
            "Suppress server version information from HTTP response headers",
            "Address all Medium findings within 30 days as part of a remediation sprint",
        ],
    )

    with open(REPORT_HTML_PATH, "w", encoding="utf-8") as fh:
        fh.write(html)

    HTML(filename=REPORT_HTML_PATH).write_pdf(REPORT_PDF_PATH)

    return REPORT_PDF_PATH
