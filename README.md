# SecureFlow (Windows Edition)

**SecureFlow** is an automated security assessment tool designed for Windows environments to streamline Static Application Security Testing (SAST) and Dynamic Application Security Testing (DAST).

## 📂 Project Structure

- **`backend/`**: Core scanning logic and CLI tool.
  - `main.py`: CLI entry point.
  - `semgrep_scan.py`, `zap_scan.py`, `headers_check.py`: Windows-optimized scanning engines.
  - `report.py`, `dashboard.py`: Reporting logic and HTML dashboard generation.
- **`frontend/`**: Web application interface.
  - `app.py`: Flask server.
  - `templates/`: UI templates (Dashboard, History, Documentation).
- **`Reports/`**: Centralized folder for all generated security reports.

## 🚀 Getting Started (Windows)

### Prerequisites
1. **Python 3.8+**: Ensure "Add Python to PATH" is checked during installation.
2. **Semgrep CLI**: Install via PowerShell/CMD:
   ```powershell
   pip install semgrep
   ```
3. **OWASP ZAP**: [Download Windows Installer](https://www.zaproxy.org/download/). 
   - Default install path: `C:\Program Files\ZAP\Zed Attack Proxy`

### Installation
```powershell
git clone https://github.com/luminomi/SecureFlow.git
cd SecureFlow
pip install -r requirements.txt
```

## 🖥️ Usage

### 1. Web Interface (Recommended)
Launch the interactive dashboard from the project root:
```powershell
python frontend/app.py
```
Open your browser to `http://127.0.0.1:5000` to start scanning.

### 2. Command Line Interface (CLI)
Run the scanner via Command Prompt or PowerShell:
```powershell
cd backend
python main.py
```

## 📊 Features
- **Native Windows Support**: Optimized for `zap.bat` and Windows pathing.
- **Auto-Reporting**: Findings are automatically saved to the `Reports\` directory.
- **Full Security Stack**: Source code analysis (SAST), Live site scanning (DAST), and HTTP Header checks.

## ⚖️ License
MIT License.
