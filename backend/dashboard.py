def generate_dashboard(url, semgrep_results, header_data, zap_report_path):
    findings  = header_data.get("findings", []) if header_data else []
    sast_list = semgrep_results if semgrep_results else []

    # ── severity counts ──────────────────────────────────────────────
    def sev_label(raw):
        r = (raw or "").upper()
        if r == "ERROR":   return "HIGH"
        if r == "WARNING": return "MEDIUM"
        return "LOW"

    sast_high = sum(1 for r in sast_list if sev_label(r.get("severity")) == "HIGH")
    sast_med  = sum(1 for r in sast_list if sev_label(r.get("severity")) == "MEDIUM")
    sast_low  = len(sast_list) - sast_high - sast_med

    hdr_high  = sum(1 for h in findings if (h.get("severity") or "").upper() == "HIGH")
    hdr_med   = sum(1 for h in findings if (h.get("severity") or "").upper() == "MEDIUM")
    hdr_low   = len(findings) - hdr_high - hdr_med

    tag_css = {
        "HIGH":   ("tag-high",   "#fef2f2", "#fecaca", "#991b1b"),
        "MEDIUM": ("tag-medium", "#fffbeb", "#fde68a", "#92400e"),
        "LOW":    ("tag-low",    "#f0fdf4", "#bbf7d0", "#14532d"),
        "ERROR":  ("tag-error",  "#fdf4ff", "#e9d5ff", "#6b21a8"),
        "INFO":   ("tag-info",   "#eff6ff", "#bfdbfe", "#1e40af"),
    }

    def tag(sev):
        cls, bg, bd, fg = tag_css.get(sev.upper(), tag_css["INFO"])
        return (f'<span style="display:inline-block;font-size:10px;font-weight:700;'
                f'letter-spacing:.06em;text-transform:uppercase;padding:2px 7px;'
                f'border-radius:5px;border:1px solid {bd};background:{bg};color:{fg};'
                f'white-space:nowrap;flex-shrink:0;margin-top:2px">{sev.upper()}</span>')

    # ── SAST rows ────────────────────────────────────────────────────
    sast_rows = ""
    for r in sast_list:
        sev = sev_label(r.get("severity"))
        msg = r.get("message") or ""
        sast_rows += f"""
            <div style="display:flex;align-items:flex-start;gap:13px;padding:14px 20px;border-bottom:1px solid #e5e7eb">
                {tag(sev)}
                <div style="flex:1;font-size:13.5px;font-weight:500;color:#111827;line-height:1.45">{msg}</div>
            </div>"""

    if not sast_rows:
        sast_rows = '<p style="padding:16px 20px;font-size:13px;color:#9ca3af">No SAST findings.</p>'

    # ── header rows ──────────────────────────────────────────────────
    header_rows = ""
    for h in findings:
        sev = (h.get("severity") or "INFO").upper()
        rec = h.get("recommendation") or ""
        fix_html = (f'<span style="display:inline-block;margin-top:7px;font-size:12px;color:#047857;'
                    f'background:#f0fdf4;border:1px solid #bbf7d0;border-radius:5px;padding:3px 9px">'
                    f'Fix &mdash; {rec}</span>') if rec else ""
        header_rows += f"""
            <div style="display:flex;align-items:flex-start;gap:13px;padding:14px 20px;border-bottom:1px solid #e5e7eb">
                {tag(sev)}
                <div style="flex:1;min-width:0">
                    <div style="font-size:13.5px;font-weight:500;color:#111827">{h.get("header", "")}</div>
                    <div style="font-size:12.5px;color:#6b7280;margin-top:3px">{h.get("risk", "")}</div>
                    {fix_html}
                </div>
            </div>"""

    if not header_rows:
        header_rows = '<p style="padding:16px 20px;font-size:13px;color:#9ca3af">No header findings.</p>'

    # ── DAST section ─────────────────────────────────────────────────
    if zap_report_path and zap_report_path != "N/A":
        dast_content = (f'<div style="padding:16px 20px">'
                        f'<a href="{zap_report_path}" target="_blank" '
                        f'style="font-size:13px;font-weight:500;color:#111827;'
                        f'text-decoration:underline;text-underline-offset:3px;'
                        f'text-decoration-color:#d1d5db">Open ZAP report &rarr;</a></div>')
    else:
        dast_content = '<p style="padding:16px 20px;font-size:13px;color:#9ca3af">No DAST report available.</p>'

    # ── stat card helper ─────────────────────────────────────────────
    def stat_card(title, count, high, med, low):
        breakdown = ""
        if high: breakdown += f'<span style="color:#991b1b">{high}H</span>&nbsp;&nbsp;'
        if med:  breakdown += f'<span style="color:#92400e">{med}M</span>&nbsp;&nbsp;'
        if low:  breakdown += f'<span style="color:#14532d">{low}L</span>'
        breakdown_html = (f'<div style="margin-top:8px;font-size:12px;font-weight:500">{breakdown}</div>'
                          if (high or med or low) else "")
        return f"""
            <div style="background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:22px 24px;flex:1">
                <div style="font-size:12px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:#6b7280">{title}</div>
                <div style="font-size:32px;font-weight:700;color:#111827;margin-top:10px;letter-spacing:-1px">{count}</div>
                {breakdown_html}
            </div>"""

    dast_status_card = f"""
            <div style="background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:22px 24px;flex:1">
                <div style="font-size:12px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:#6b7280">DAST scan</div>
                <div style="font-size:32px;font-weight:700;color:#111827;margin-top:10px;letter-spacing:-1px">Done</div>
                <div style="margin-top:8px;font-size:12px;color:#9ca3af">Baseline scan completed</div>
            </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureFlow &mdash; Scan Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #fafafa;
            color: #111827;
            min-height: 100vh;
            -webkit-font-smoothing: antialiased;
        }}
    </style>
</head>
<body>

<header style="height:56px;padding:0 32px;display:flex;align-items:center;justify-content:space-between;
               background:#fff;border-bottom:1px solid #e5e7eb">
    <span style="font-size:15px;font-weight:700;letter-spacing:-0.3px">SecureFlow</span>
    <span style="font-size:12px;color:#9ca3af">Scan report</span>
</header>

<div style="max-width:780px;margin:0 auto;padding:48px 32px 96px">

    <div style="margin-bottom:32px">
        <h1 style="font-size:26px;font-weight:700;letter-spacing:-0.5px;line-height:1.2">Scan Results</h1>
        <p style="margin-top:8px;font-size:14px;color:#6b7280">Target &mdash; {url}</p>
    </div>

    <!-- stat cards -->
    <div style="display:flex;gap:12px;margin-bottom:32px">
        {stat_card("SAST findings", len(sast_list), sast_high, sast_med, sast_low)}
        {stat_card("Header issues", len(findings), hdr_high, hdr_med, hdr_low)}
        {dast_status_card}
    </div>

    <!-- SAST group -->
    <div style="background:#fff;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;margin-bottom:12px">
        <div style="padding:13px 20px;font-size:12px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;
                    color:#6b7280;background:#fafafa;border-bottom:1px solid #e5e7eb;
                    display:flex;justify-content:space-between;align-items:center">
            <span>Static analysis</span>
            <span style="font-size:11px;font-weight:500;letter-spacing:0;text-transform:none;color:#9ca3af">
                {len(sast_list)} finding{"s" if len(sast_list) != 1 else ""}
            </span>
        </div>
        {sast_rows}
    </div>

    <!-- Headers group -->
    <div style="background:#fff;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;margin-bottom:12px">
        <div style="padding:13px 20px;font-size:12px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;
                    color:#6b7280;background:#fafafa;border-bottom:1px solid #e5e7eb;
                    display:flex;justify-content:space-between;align-items:center">
            <span>HTTP headers</span>
            <span style="font-size:11px;font-weight:500;letter-spacing:0;text-transform:none;color:#9ca3af">
                {len(findings)} finding{"s" if len(findings) != 1 else ""}
            </span>
        </div>
        {header_rows}
    </div>

    <!-- DAST group -->
    <div style="background:#fff;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;margin-bottom:12px">
        <div style="padding:13px 20px;font-size:12px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;
                    color:#6b7280;background:#fafafa;border-bottom:1px solid #e5e7eb">
            DAST report
        </div>
        {dast_content}
    </div>

</div>
</body>
</html>"""

    with open("dashboard.html", "w", encoding="utf-8") as f:
        f.write(html)

    print("[+] Dashboard generated: dashboard.html")
