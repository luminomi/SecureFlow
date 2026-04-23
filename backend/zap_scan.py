import subprocess
import os
import platform
from datetime import datetime


def _zap_binary():
    system = platform.system()
    if system == "Windows":
        return r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat"
    elif system == "Darwin":
        return "/Applications/ZAP.app/Contents/Java/zap.sh"
    else:
        return "/opt/zaproxy/zap.sh"


def run_zap(url):
    try:
        zap_bin      = _zap_binary()
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        report_path  = os.path.join(project_root, "zap_report.html")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        zap_home  = os.path.join(os.path.expanduser("~"), f"ZAP_{timestamp}")
        os.makedirs(zap_home, exist_ok=True)

        if platform.system() == "Windows":
            zap_dir = os.path.dirname(zap_bin)
            command = (
                f'cd /d "{zap_dir}" && '
                f'zap.bat -cmd -dir "{zap_home}" '
                f'-quickurl {url} '
                f'-quickout "{report_path}"'
            )
            subprocess.run(command, shell=True, check=False)
        else:
            subprocess.run(
                [zap_bin, "-cmd", "-dir", zap_home,
                 "-quickurl", url, "-quickout", report_path],
                check=False
            )

        return {"status": "completed", "report": report_path}

    except Exception as e:
        print(f"[!] ZAP scan error: {e}")
        return {"error": str(e), "report": "N/A"}
