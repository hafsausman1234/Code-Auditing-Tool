import os
import json
import subprocess
import multiprocessing
from prettytable import PrettyTable
from html import escape

CVE_MAP_PATH = "vuln_to_cve_mapping.json"
MITIGATION_PATH = "vuln_mitigations.json"

def load_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except:
        return {}

def run_bandit(target):
    try:
        cmd = ["bandit", "-r", target, "-f", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if not result.stdout.strip():
            return []
        output = json.loads(result.stdout)
        return [{
            "issue": item.get("issue_text", ""),
            "file": item.get("filename", ""),
            "line_number": item.get("line_number", ""),
            "severity": item.get("issue_severity", "LOW").upper()
        } for item in output.get("results", [])]
    except:
        return []

def run_flake8(target):
    try:
        result = subprocess.run(
            ["flake8", target, "--format=%(path)s::%(row)d::%(col)d::%(code)s::%(text)s"],
            capture_output=True, text=True
        )
        lines = result.stdout.strip().split('\n')
        issues = []
        for line in lines:
            parts = line.split('::')
            if len(parts) != 5: continue
            file_path, row, _, code, text = parts
            if code.startswith("F"):
                issues.append({
                    "issue": f"{code}: {text}",
                    "file": file_path,
                    "line_number": row,
                    "severity": "HIGH"
                })
        return issues
    except:
        return []

def run_semgrep(target):
    try:
        result = subprocess.run(
            ["semgrep", "--config=auto", "--json", "-q", target],
            capture_output=True, text=True
        )
        output = json.loads(result.stdout)
        return [{
            "issue": item.get("check_id", ""),
            "file": item.get("path", ""),
            "line_number": item.get("start", {}).get("line", ""),
            "severity": item.get("extra", {}).get("severity", "LOW").upper()
        } for item in output.get("results", [])]
    except:
        return []

def execute_tool(args):
    func, target = args
    return func(target)

def run_audits(target):
    tasks = [
        (run_bandit, target),
        (run_flake8, target),
        (run_semgrep, target)
    ]
    with multiprocessing.Pool(processes=3) as pool:
        results = pool.map(execute_tool, tasks)
    issues = [issue for sublist in results for issue in sublist]

    cve_map = load_json(CVE_MAP_PATH)
    mitigation_map = load_json(MITIGATION_PATH)

    for issue in issues:
        issue_text = issue["issue"].lower()
        matched_cves = []
        mitigation_key = ""
        for key in cve_map:
            key_lower = key.lower().replace("_", " ")
            if key_lower in issue_text:
                matched_cves.extend(cve_map[key])
                mitigation_key = key
        issue["cves"] = sorted(set(matched_cves))
        issue["mitigation"] = mitigation_map.get(mitigation_key, {}).get("mitigation", "No mitigation available.")
        issue["keyword"] = mitigation_key or "unknown"
    return issues

def colorize(text, severity):
    color_codes = {
        "HIGH": "\033[91m",   # Red
        "MEDIUM": "\033[93m", # Yellow/Orange
        "LOW": "\033[33m"     # Yellow
    }
    return f"{color_codes.get(severity, '')}{text}\033[0m"

def print_summary_table(issues):
    # Build colorized table
    table = PrettyTable()
    table.field_names = ["File", "Line", "Severity", "Vulnerability", "CVEs"]
    
    # Set the column widths for better formatting
    table.max_width = 30
    table.align = "l"  # Align all columns to the left

    for issue in issues:
        severity_colored = colorize(issue["severity"], issue["severity"])
        table.add_row([
            issue["file"],
            issue["line_number"],
            severity_colored,
            issue["issue"],
            ", ".join(issue["cves"])
        ])

    # Box top
    print("\n" + "═" * 100)
    print(f"{colorize('AUDIT SUMMARY', 'MEDIUM'):^100}")
    print("═" * 100)
    print(table)
    print("═" * 100 + "\n")

def generate_html_report(issues):
    html = ['<html><head><title>Audit Report</title></head><body>']
    html.append('<h1>Code Audit Report</h1>')
    grouped = {}
    for i in issues:
        grouped.setdefault(i["file"], []).append(i)
    for file, items in grouped.items():
        html.append(f"<h2>File: {escape(file)}</h2>")
        html.append("<table border='1' cellpadding='5'><tr><th>Line</th><th>Vulnerability</th><th>CVEs</th><th>Mitigation</th></tr>")
        for i in items:
            html.append(f"<tr><td>{i['line_number']}</td><td>{escape(i['issue'])}</td>"
                        f"<td>{', '.join(i['cves'])}</td><td>{escape(i['mitigation'])}</td></tr>")
        html.append("</table><br>")
    html.append('</body></html>')
    with open("audit_report.html", "w", encoding="utf-8") as f:
        f.write("\n".join(html))

def main():
    target = input(" Enter a file or directory to audit: ").strip()
    if not os.path.exists(target):
        print(" Error: Path does not exist!")
        return

    print("\n Running audits, please wait...")
    issues = run_audits(target)
    print_summary_table(issues)
    generate_html_report(issues)
    print(" HTML report saved as 'audit_report.html'.")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
