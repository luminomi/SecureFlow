from flask import Flask, render_template, request, abort
import sys
import os
import re
import glob

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.semgrep_scan import run_semgrep
from backend.zap_scan import run_zap
from backend.headers_check import check_headers
from backend.report import generate_report_data, generate_text_report
from backend.dashboard import generate_dashboard

app = Flask(__name__)

# Root of the SecureFlow project — where reports are saved
REPORTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _parse_report_meta(filepath):
    meta = {"target": "N/A", "code_path": "N/A", "total": "0",
            "high": "0", "medium": "0", "low": "0"}
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("Target URL"):
                    meta["target"] = line.split(":", 1)[1].strip()
                elif line.startswith("Code Path"):
                    meta["code_path"] = line.split(":", 1)[1].strip()
                elif line.startswith("Total Issues"):
                    meta["total"] = line.split(":", 1)[1].strip()
                elif re.match(r"^HIGH\s*:", line):
                    meta["high"] = line.split(":", 1)[1].strip()
                elif re.match(r"^MEDIUM\s*:", line):
                    meta["medium"] = line.split(":", 1)[1].strip()
                elif re.match(r"^LOW\s*:", line):
                    meta["low"] = line.split(":", 1)[1].strip()
    except Exception:
        pass
    return meta


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        code_path = request.form.get("code_path")
        url       = request.form.get("url")
        scan_type = request.form.get("scan_type")

        semgrep_results = []
        zap_result      = {}
        header_data     = {}

        if scan_type in ["sast", "both"] and code_path:
            print(f"[+] Running SAST on {code_path}")
            semgrep_results = run_semgrep(code_path)

        if scan_type in ["dast", "both"] and url:
            if not url.startswith("http"):
                url = "http://" + url
            print(f"[+] Running DAST on {url}")
            zap_result  = run_zap(url)
            print("[+] Checking HTTP Security Headers...")
            header_data = check_headers(url)

        result = generate_report_data(semgrep_results, zap_result.get("report", "N/A"))

        if header_data:
            result["headers"] = header_data

        # Save text report and dashboard after every scan
        generate_text_report(result, code_path, url, output_dir=REPORTS_DIR)
        generate_dashboard(url or "N/A", semgrep_results, header_data,
                           zap_result.get("report", "N/A"))

    return render_template("index.html", result=result)


@app.route("/reports")
def reports():
    pattern = os.path.join(REPORTS_DIR, "report_*.txt")
    files   = sorted(glob.glob(pattern), reverse=True)

    report_list = []
    for f in files:
        fname = os.path.basename(f)
        m = re.match(r"report_(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})\.txt$", fname)
        if m:
            yr, mo, dy, hr, mn, sc = m.groups()
            dt = f"{yr}-{mo}-{dy}  {hr}:{mn}:{sc}"
        else:
            dt = "Unknown"

        meta = _parse_report_meta(f)
        report_list.append({"filename": fname, "datetime": dt, "meta": meta})

    return render_template("reports.html", reports=report_list)


@app.route("/reports/<filename>")
def view_report(filename):
    if not re.match(r"^report_\d{8}_\d{6}\.txt$", filename):
        abort(404)
    filepath = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(filepath):
        abort(404)
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    meta = _parse_report_meta(filepath)
    return render_template("report_detail.html", filename=filename,
                           content=content, meta=meta)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
