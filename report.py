import datetime

def generate_report_data(semgrep_results, zap_report_path):

    high = medium = low = 0

    # ---- SAST ----
    sast = []
    if semgrep_results:
        for i in semgrep_results:
            sev_raw = (i.get("severity") or "").upper()
            if sev_raw == "ERROR":
                sev = "HIGH"; high += 1
            elif sev_raw == "WARNING":
                sev = "MEDIUM"; medium += 1
            else:
                sev = "LOW"; low += 1

            sast.append({
                "severity": sev,
                "message": i.get("message")
            })

    # ---- DAST (ZAP) summary ----
    dast = {
        "status": "Completed",
        "summary": "OWASP ZAP baseline scan executed (includes header checks, passive findings).",
        "report_path": zap_report_path
    }

    report = {
        "summary": {
            "total": high + medium + low,
            "high": high,
            "medium": medium,
            "low": low
        },
        "sast": sast,
        "dast": dast
    }
    return report


def generate_text_report(report, code_path, url):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"report_{ts}.txt"

    lines = []
    lines.append("=== SecureFlow Security Report ===\n")
    lines.append(f"Generated At: {ts}")
    lines.append(f"Code Path: {code_path}")
    lines.append(f"Target URL: {url}\n")

    lines.append("=== Executive Summary ===")
    lines.append(f"Total Issues: {report['summary']['total']}")
    lines.append(f"HIGH: {report['summary']['high']}")
    lines.append(f"MEDIUM: {report['summary']['medium']}")
    lines.append(f"LOW: {report['summary']['low']}\n")

    lines.append("=== SAST Findings (Semgrep) ===")
    if report["sast"]:
        for f in report["sast"]:
            lines.append(f"[{f['severity']}] {f['message']}")
    else:
        lines.append("No SAST issues found.")
    lines.append("")

    lines.append("=== DAST Summary (OWASP ZAP) ===")
    lines.append(report["dast"]["summary"])
    if report["dast"]["report_path"]:
        lines.append(f"Detailed Report: {report['dast']['report_path']}")
    lines.append("")

    lines.append("=== Recommendations ===")
    lines.append("- Review ZAP findings (including header-related alerts) in the detailed report.")
    lines.append("- Fix high/medium issues first.")
    lines.append("- Enforce secure headers and HTTPS where applicable.")
    lines.append("- Integrate scans into CI/CD for continuous security.\n")

    lines.append("=== End of Report ===")

    with open(fname, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return fname


def generate_report(code_path, url, semgrep_results, zap_report_path, header_data):
    """
    Main entry point for report generation called by main.py
    """
    # 1. Prepare data structure
    report_data = generate_report_data(semgrep_results, zap_report_path)
    
    # 2. Add header findings to report data (if not already there)
    if header_data:
        report_data["headers"] = header_data

    # 3. Generate text report
    txt_report = generate_text_report(report_data, code_path, url)
    print(f"[+] Text report generated: {txt_report}")

    # 4. Generate dashboard
    from dashboard import generate_dashboard
    generate_dashboard(url, semgrep_results, header_data, zap_report_path)

    return txt_report