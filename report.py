from datetime import datetime

def generate_report(code_path, url, semgrep_results, zap_report_path, header_data):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{timestamp}.txt"

    severity_count = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "ERROR": 0,
        "UNKNOWN": 0
    }

    # Count SAST severities
    for v in semgrep_results:
        sev = v.get("severity", "UNKNOWN").upper()
        if sev in severity_count:
            severity_count[sev] += 1
        else:
            severity_count["UNKNOWN"] += 1

    # Header issues count as MEDIUM
    if header_data and "findings" in header_data:
        severity_count["MEDIUM"] += len(header_data["findings"])

    with open(filename, "w", encoding="utf-8") as f:

        # ===== HEADER =====
        f.write("=" * 60 + "\n")
        f.write("              SECUREFLOW SECURITY REPORT\n")
        f.write("=" * 60 + "\n\n")

        # ===== EXECUTIVE SUMMARY =====
        f.write("1. EXECUTIVE SUMMARY\n")
        f.write("-" * 60 + "\n")
        f.write("This report presents the results of an automated security assessment\n")
        f.write("performed using SecureFlow, including static analysis, dynamic scanning,\n")
        f.write("and HTTP transaction inspection.\n\n")

        # ===== SCOPE =====
        f.write("2. SCOPE\n")
        f.write("-" * 60 + "\n")

        if code_path != "N/A" and url != "N/A":
            scan_type = "SAST + DAST"
        elif code_path != "N/A":
            scan_type = "SAST Only"
        else:
            scan_type = "DAST Only"

        f.write(f"SAST Target : {code_path}\n")
        f.write(f"DAST Target : {url}\n")
        f.write(f"Scan Type   : {scan_type}\n\n")

        # ===== SEVERITY =====
        f.write("3. SEVERITY OVERVIEW\n")
        f.write("-" * 60 + "\n")
        for k, v in severity_count.items():
            f.write(f"{k:<7}: {v}\n")
        f.write("\n")

        # ===== FINDINGS =====
        f.write("4. FINDINGS\n")
        f.write("-" * 60 + "\n")

        # ---- SAST ----
        f.write("\n4.1 SAST Findings\n")
        f.write("-" * 40 + "\n")

        if not semgrep_results:
            f.write("No vulnerabilities found.\n")
        else:
            for i, v in enumerate(semgrep_results, 1):
                f.write(f"{i}. [{v.get('severity')}] {v.get('message')}\n")
                f.write(f"   Rule ID: {v.get('rule_id')}\n\n")

        # ---- HEADERS ----
        f.write("\n4.2 HTTP Security Headers Analysis\n")
        f.write("-" * 40 + "\n")

        if not header_data or "findings" not in header_data:
            f.write("Header analysis not available.\n")
        elif not header_data["findings"]:
            f.write("All important security headers are present.\n")
        else:
            for h in header_data["findings"]:
                f.write(f"[MEDIUM] Missing {h['header']} - {h['risk']}\n")

        # ---- HTTP TRANSACTION ----
        f.write("\n4.3 HTTP TRANSACTION ANALYSIS\n")
        f.write("-" * 40 + "\n")

        if not header_data or "status_code" not in header_data:
            f.write("Transaction data not available.\n")
        else:
            f.write(f"Request: GET {header_data['url']}\n\n")
            f.write(f"Response Status: {header_data['status_code']}\n\n")

            f.write("Important Headers:\n")
            for h in ["Server", "X-Powered-By", "Content-Type"]:
                val = header_data["headers"].get(h)
                if val:
                    f.write(f"{h}: {val}\n")

            f.write("\nSecurity Insights:\n")
            for a in header_data.get("analysis", []):
                f.write(f"- {a}\n")

        # ---- DAST ----
        f.write("\n5. DAST SUMMARY\n")
        f.write("-" * 60 + "\n")

        if zap_report_path and zap_report_path != "N/A":
            f.write("ZAP scan completed successfully.\n")
            f.write(f"Detailed report: {zap_report_path}\n")
        else:
            f.write("DAST not executed.\n")

        # ---- RECOMMENDATIONS ----
        f.write("\n6. RECOMMENDATIONS\n")
        f.write("-" * 60 + "\n")
        f.write("- Avoid subprocess with shell=True\n")
        f.write("- Add Content-Security-Policy header\n")
        f.write("- Enable X-Frame-Options\n")
        f.write("- Use HTTPS with HSTS\n")

        # ---- CONCLUSION ----
        f.write("\n7. CONCLUSION\n")
        f.write("-" * 60 + "\n")
        f.write("Security issues detected. Remediation recommended.\n")

    print(f"\n[+] Report generated: {filename}")