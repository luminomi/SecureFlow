def generate_dashboard(url, semgrep_results, header_data, zap_report_path):
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>SecureFlow Dashboard</title>
    <style>
        body {{
            font-family: 'Segoe UI', sans-serif;
            background-color: #0f172a;
            color: #e2e8f0;
            margin: 0;
            padding: 0;
        }}

        .container {{
            padding: 40px;
        }}

        h1 {{
            font-size: 32px;
            margin-bottom: 10px;
        }}

        .subtitle {{
            color: #94a3b8;
            margin-bottom: 30px;
        }}

        .cards {{
            display: flex;
            gap: 20px;
        }}

        .card {{
            background: #1e293b;
            padding: 20px;
            border-radius: 12px;
            flex: 1;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }}

        .card h2 {{
            margin-top: 0;
            font-size: 18px;
            color: #cbd5f5;
        }}

        .stat {{
            font-size: 28px;
            margin-top: 10px;
        }}

        .high {{ color: #ef4444; }}
        .medium {{ color: #f59e0b; }}
        .low {{ color: #22c55e; }}

        .section {{
            margin-top: 40px;
        }}

        .btn {{
            display: inline-block;
            margin-top: 15px;
            padding: 10px 16px;
            background: #3b82f6;
            color: white;
            text-decoration: none;
            border-radius: 8px;
        }}

    </style>
</head>
<body>

<div class="container">
    <h1>SecureFlow Dashboard</h1>
    <div class="subtitle">Target: {url}</div>

    <div class="cards">
        <div class="card">
            <h2>SAST Findings</h2>
            <div class="stat">{len(semgrep_results)}</div>
        </div>

        <div class="card">
            <h2>Header Issues</h2>
            <div class="stat">{len(header_data.get("findings", []))}</div>
        </div>

        <div class="card">
            <h2>DAST Scan</h2>
            <div class="stat">Completed</div>
            <a class="btn" href="{zap_report_path}" target="_blank">View ZAP Report</a>
        </div>
    </div>

    <div class="section">
        <h2>Header Findings</h2>
"""

    for h in header_data.get("findings", []):
        html += f"""
        <div class="card">
            <strong class="{h['severity'].lower()}">[{h['severity']}]</strong>
            {h['header']} - {h['risk']}
        </div>
        """

    html += """
    </div>

</div>
</body>
</html>
"""

    with open("dashboard.html", "w", encoding="utf-8") as f:
        f.write(html)

    print("[+] Dashboard generated: dashboard.html")