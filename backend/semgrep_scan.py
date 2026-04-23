import subprocess
import json

def run_semgrep(target_path):
    try:
        result = subprocess.run(
            [
                "semgrep",
                "scan",
                "--config", "auto",
                "--json",
                target_path
            ],
            capture_output=True,
            text=True,
            encoding="utf-8"
        )

        output = result.stdout.strip()

        if not output:
            stderr = result.stderr.strip()
            error_msg = stderr if stderr else f"semgrep exited with code {result.returncode} and no output"
            return [{"error": error_msg}]

        data = json.loads(output)

        findings = []
        for res in data.get("results", []):
            findings.append({
                "rule_id": res.get("check_id"),
                "message": res.get("extra", {}).get("message"),
                "severity": res.get("extra", {}).get("severity")
            })

        return findings

    except Exception as e:
        return [{"error": str(e)}]