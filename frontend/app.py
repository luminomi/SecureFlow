from flask import Flask, render_template, request, jsonify
import sys

import os

# Add parent directory to sys.path to allow importing from backend
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.semgrep_scan import run_semgrep
from backend.zap_scan import run_zap
from backend.headers_check import check_headers
from backend.report import generate_report_data


app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        code_path = request.form.get("code_path")
        url = request.form.get("url")
        scan_type = request.form.get("scan_type")

        semgrep_results = []
        zap_result = {}
        header_data = {}

        if scan_type in ["sast", "both"] and code_path:
            print(f"[+] Running SAST on {code_path}")
            semgrep_results = run_semgrep(code_path)

        if scan_type in ["dast", "both"] and url:
            if not url.startswith("http"):
                url = "http://" + url
            print(f"[+] Running DAST on {url}")
            zap_result = run_zap(url)
            print("[+] Checking HTTP Security Headers...")
            header_data = check_headers(url)

        # Aggregate data for the template
        result = generate_report_data(
            semgrep_results, 
            zap_result.get("report", "N/A")
        )
        
        # Add header data manually since generate_report_data doesn't include it in its default structure
        if header_data:
            result["headers"] = header_data

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True, port=5000)