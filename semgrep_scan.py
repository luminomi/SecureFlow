import subprocess
import json

def run_semgrep():
    try:
        result = subprocess.run(
            ["semgrep", "scan", "--config", "p/python", "--json", "--quiet"],
            capture_output=True,
            text=True
        )

        # Try stdout first, then stderr
        output = result.stdout.strip() if result.stdout.strip() else result.stderr.strip()

        if not output:
            return [{"error": "No output from semgrep"}]

        try:
            data = json.loads(output)
        except:
            return [{"error": "Invalid JSON", "raw": output[:300]}]

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