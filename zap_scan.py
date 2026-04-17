import subprocess
import os
from datetime import datetime

def run_zap(url):
    try:
        zap_dir = r"C:\Program Files\ZAP\Zed Attack Proxy"
        report_path = r"C:\Users\Shriem\Desktop\SecureFlow\zap_report.html"

        # Create unique temp directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        zap_home = rf"C:\Users\Shriem\ZAP_{timestamp}"

        # Create directory
        os.makedirs(zap_home, exist_ok=True)

        command = (
            f'cd /d "{zap_dir}" && '
            f'zap.bat -cmd -dir "{zap_home}" '
            f'-quickurl {url} '
            f'-quickout "{report_path}"'
        )

        subprocess.run(command, shell=True)

        return {
            "status": "completed",
            "report": report_path
        }

    except Exception as e:
        return {"error": str(e)}