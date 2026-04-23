from report import generate_report_data, generate_text_report

# inside your POST handling (both case):
semgrep_results = run_semgrep(code_path)
zap_result = run_zap(url)

report = generate_report_data(
    semgrep_results,
    zap_result.get("report")
)

generate_text_report(report, code_path, url)

result = report