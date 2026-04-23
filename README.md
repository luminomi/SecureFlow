# SecureFlow

**SecureFlow** is an automated security assessment tool designed to streamline both Static Application Security Testing (SAST) and Dynamic Application Security Testing (DAST). It provides a unified interface to scan source code for vulnerabilities and assess live web applications for common security flaws and misconfigurations.

## 🚀 Features

- **SAST (Static Analysis)**: Integrates with **Semgrep** to perform deep scans on Python source code, identifying potential security risks like SQL injection, insecure command execution, and more.
- **DAST (Dynamic Analysis)**: Leverages **OWASP ZAP** to perform baseline scans on live URLs, detecting common web vulnerabilities.
- **HTTP Header Analysis**: Automatically checks for missing or misconfigured security headers (e.g., HSTS, CSP, X-Frame-Options) using a customizable ruleset.
- **Unified Reporting**: Generates comprehensive text-based reports and an interactive HTML dashboard for quick visualization of findings.
- **Web Interface (Experimental)**: Includes a preliminary web dashboard for managing scans via a browser.

## 🛠️ Prerequisites

Before running SecureFlow, ensure you have the following installed:

1. **Python 3.8+**
2. **Semgrep CLI**: `pip install semgrep`
3. **OWASP ZAP**: [Download and install OWASP ZAP](https://www.zaproxy.org/download/).
   - *Note: The default `zap_scan.py` assumes a standard Windows installation path. Adjust accordingly for Linux/macOS.*

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone git@github.com:Raghaverma/SecureFlow.git
   cd SecureFlow
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 🖥️ Usage

### Option 1: CLI (Command Line)
Run the main CLI tool to start a scan:
```bash
python main.py
```

### Option 2: Web Interface (Frontend)
SecureFlow now includes a web interface for a more interactive experience:
```bash
python app.py
```
Then navigate to `http://127.0.0.1:5000` in your browser.

### Scan Options:

1. **Run SAST**: Provide the local path to your Python source code.
2. **Run DAST**: Provide the target URL of the application to scan.
3. **Run Both**: Perform a full assessment including code analysis, dynamic scanning, and header checks.

## 📂 Project Structure

- `main.py`: CLI entry point.
- `semgrep_scan.py`: SAST logic using Semgrep.
- `zap_scan.py`: DAST logic using OWASP ZAP.
- `headers_check.py`: HTTP security header analysis.
- `report.py`: Report generation logic (Text & HTML).
- `dashboard.py`: HTML dashboard generator.
- `headers_rules.json`: Configurable rules for header analysis.
- `templates/`: HTML templates for the web interface.

## 📝 Roadmap

- [ ] Full Flask/FastAPI web integration.
- [ ] Support for more SAST languages (JS, Go, etc.).
- [ ] Integration with CI/CD pipelines (GitHub Actions, Jenkins).
- [ ] Export reports to PDF/JSON formats.

## ⚖️ License

This project is licensed under the MIT License - see the LICENSE file for details.
