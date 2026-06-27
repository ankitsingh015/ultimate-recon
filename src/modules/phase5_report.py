import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

class Phase5:
    NAME = "Report Generation"

    def run(self, orch) -> dict:
        out = orch.output_dir
        target = orch.target
        db = orch.db

        print("  [*] Generating comprehensive HTML report...")

        report_path = out / "report.html"
        stats = db.get_stats(1) if hasattr(db, 'get_stats') else {}

        all_results_dir = orch.all_results_dir

        subdomains_found = []
        sub_file = all_results_dir / "final-subdomains.txt"
        if sub_file.exists():
            with open(sub_file) as f:
                subdomains_found = [l.strip() for l in f if l.strip()]

        live_hosts = []
        live_file = all_results_dir / "alive-hosts.txt"
        if live_file.exists():
            with open(live_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        parts = line.split()
                        live_hosts.append(parts[0])

        urls_found = []
        urls_file = all_results_dir / "all-urls.txt"
        if urls_file.exists():
            with open(urls_file) as f:
                urls_found = [l.strip() for l in f if l.strip()]

        vulns = []
        vulns_file = out / "vulns" / "nuclei-results.txt"
        if vulns_file.exists():
            with open(vulns_file) as f:
                vulns = [l.strip() for l in f if l.strip()]

        sqli_vulns = []
        sqli_file = out / "vulns" / "sqli.txt"
        if sqli_file.exists() and sqli_file.stat().st_size:
            with open(sqli_file) as f:
                sqli_vulns = [l.strip() for l in f if l.strip()]

        xss_vulns = []
        xss_file = out / "vulns" / "xss.txt"
        if xss_file.exists() and xss_file.stat().st_size:
            with open(xss_file) as f:
                xss_vulns = [l.strip() for l in f if l.strip()]

        lfi_vulns = []
        lfi_file = out / "vulns" / "lfi.txt"
        if lfi_file.exists() and lfi_file.stat().st_size:
            with open(lfi_file) as f:
                lfi_vulns = [l.strip() for l in f if l.strip()]

        secrets_found = []
        secrets_file = all_results_dir / "js-secrets.txt"
        if secrets_file.exists() and secrets_file.stat().st_size:
            with open(secrets_file) as f:
                secrets_found = [l.strip() for l in f if l.strip() if l.strip()[:1].isalpha()]

        tech_stack = {}
        tech_file = all_results_dir / "tech-stack.json"
        if tech_file.exists():
            with open(tech_file) as f:
                try:
                    tech_stack = json.load(f)
                except Exception:
                    tech_stack = {}

        analysis_dir = out / "analysis"
        highlights = []
        highlights_file = analysis_dir / "highlights.txt"
        if highlights_file.exists():
            with open(highlights_file) as f:
                highlights = [l.strip() for l in f if l.strip() and l.strip().startswith("⭐")]

        html = self._generate_html(
            target=target,
            stats=stats,
            subdomains=subdomains_found[:500],
            live_hosts=live_hosts,
            urls=urls_found[:1000],
            vulns=vulns[:200],
            sqli=sqli_vulns[:50],
            xss=xss_vulns[:50],
            lfi=lfi_vulns[:50],
            secrets=secrets_found[:50],
            tech_stack=tech_stack,
            highlights=highlights[:50],
            out_dir=out,
            analysis_dir=analysis_dir
        )

        with open(report_path, "w") as f:
            f.write(html)

        print(f"    -> Report generated: {report_path}")
        print(f"    -> Open in browser: file://{report_path.resolve()}")

        return {"report_path": str(report_path)}

    def _generate_html(self, target: str, stats: dict, subdomains: list,
                       live_hosts: list, urls: list, vulns: list,
                       sqli: list, xss: list, lfi: list, secrets: list,
                       tech_stack: dict, highlights: list,
                       out_dir: Path, analysis_dir: Path) -> str:

        severity_counts = {
            "critical": len(sqli),
            "high": len(xss) + len(lfi) + len(vulns),
            "medium": len(secrets),
            "low": 0
        }

        screenshot_dir = out_dir / "screenshots"
        screenshots = []
        if screenshot_dir.exists():
            screenshots = [f for f in sorted(screenshot_dir.glob("*.png"))[:12]]

        sub_html = "".join(
            f"<tr><td>{s}</td></tr>\n" for s in subdomains[:200]
        )
        live_html = "".join(
            f"<tr><td>{h}</td></tr>\n" for h in live_hosts[:100]
        )
        vuln_html = "".join(
            f"<tr><td class='sev-high'>HIGH</td><td>{v}</td></tr>\n" for v in vulns[:100]
        )
        sqli_html = "".join(
            f"<tr><td class='sev-critical'>CRITICAL</td><td>{s}</td></tr>\n" for s in sqli[:50]
        )
        xss_html = "".join(
            f"<tr><td class='sev-high'>HIGH</td><td>{x}</td></tr>\n" for x in xss[:50]
        )
        lfi_html = "".join(
            f"<tr><td class='sev-high'>HIGH</td><td>{l}</td></tr>\n" for l in lfi[:50]
        )
        secrets_html = "".join(
            f"<tr><td class='sev-medium'>MEDIUM</td><td>{s}</td></tr>\n" for s in secrets[:50]
        )

        tech_html = "".join(
            f"<tr><td>{t}</td><td>{c}</td></tr>\n" for t, c in sorted(tech_stack.items(), key=lambda x: -x[1])[:30]
        )

        highlights_html = "".join(
            f"<li>{h}</li>\n" for h in highlights[:50]
        )

        screenshot_html = ""
        for ss in screenshots:
            rel = ss.relative_to(out_dir)
            screenshot_html += f'<img src="{rel}" class="screenshot" onclick="window.open(this.src)" />\n'

        total_findings = sum(severity_counts.values()) + len(vulns)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ultimate Recon Report — {target}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0f; color: #e0e0e0; line-height: 1.6; }}
.header {{ background: linear-gradient(135deg, #0f0f1a, #1a1a2e); padding: 30px 40px; border-bottom: 2px solid #00ff88; }}
.header h1 {{ color: #00ff88; font-size: 28px; }}
.header .sub {{ color: #888; font-size: 14px; }}
.stats-bar {{ display: flex; gap: 20px; padding: 20px 40px; background: #12121e; flex-wrap: wrap; }}
.stat-card {{ background: #1a1a2e; border-radius: 10px; padding: 15px 25px; min-width: 120px; border: 1px solid #2a2a3e; }}
.stat-card .num {{ font-size: 28px; font-weight: bold; }}
.stat-card .label {{ font-size: 12px; color: #888; text-transform: uppercase; }}
.critical {{ color: #ff4444; }} .high {{ color: #ff8800; }} .medium {{ color: #ffcc00; }} .low {{ color: #66ccff; }}
.container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
.section {{ background: #12121e; border-radius: 10px; margin: 20px 0; border: 1px solid #2a2a3e; overflow: hidden; }}
.section h2 {{ background: #1a1a2e; padding: 15px 20px; font-size: 16px; text-transform: uppercase; color: #00ff88; border-bottom: 1px solid #2a2a3e; }}
.section .content {{ padding: 20px; overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #1a1a2e; }}
th {{ background: #1a1a2e; color: #00ff88; font-size: 11px; text-transform: uppercase; }}
tr:hover {{ background: #1a1a2e; }}
.sev-critical {{ color: #ff4444; font-weight: bold; }}
.sev-high {{ color: #ff8800; font-weight: bold; }}
.sev-medium {{ color: #ffcc00; }}
pre {{ background: #0a0a0f; padding: 10px; border-radius: 5px; font-size: 12px; overflow-x: auto; max-height: 300px; }}
.screenshots {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 15px; }}
.screenshots img {{ width: 100%; border-radius: 5px; border: 1px solid #2a2a3e; cursor: pointer; transition: transform 0.2s; }}
.screenshots img:hover {{ transform: scale(1.02); }}
.highlights {{ list-style: none; }}
.highlights li {{ padding: 10px 15px; border-left: 3px solid #00ff88; margin: 8px 0; background: #1a1a2e; border-radius: 0 5px 5px 0; }}
.tabs {{ display: flex; gap: 5px; padding: 15px 20px; background: #0f0f1a; border-bottom: 1px solid #2a2a3e; }}
.tab {{ padding: 8px 16px; border-radius: 5px; cursor: pointer; background: #1a1a2e; border: 1px solid #2a2a3e; font-size: 13px; color: #888; }}
.tab.active {{ background: #00ff88; color: #000; border-color: #00ff88; }}
.tab:hover {{ border-color: #00ff88; }}
.footer {{ text-align: center; padding: 30px; color: #555; font-size: 12px; }}
@media (max-width: 768px) {{ .stats-bar {{ flex-direction: column; }} .stat-card {{ min-width: auto; }} }}
</style>
</head>
<body>
<div class="header">
<h1>Ultimate Recon Report</h1>
<div class="sub">Target: {target} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Total Findings: {total_findings}</div>
</div>

<div class="stats-bar">
<div class="stat-card"><div class="num">{len(subdomains)}</div><div class="label">Subdomains</div></div>
<div class="stat-card"><div class="num">{len(live_hosts)}</div><div class="label">Live Hosts</div></div>
<div class="stat-card"><div class="num">{len(urls)}</div><div class="label">URLs</div></div>
<div class="stat-card"><div class="num critical">{severity_counts['critical']}</div><div class="label">Critical</div></div>
<div class="stat-card"><div class="num high">{severity_counts['high']}</div><div class="label">High</div></div>
<div class="stat-card"><div class="num medium">{severity_counts['medium']}</div><div class="label">Medium</div></div>
<div class="stat-card"><div class="num">{len(screenshots)}</div><div class="label">Screenshots</div></div>
</div>

<div class="container">

<div class="section">
<h2>⭐ Highlights</h2>
<div class="content">
<ul class="highlights">
{highlights_html if highlights_html else '<li>No critical highlights. See full findings below.</li>'}
</ul>
</div>
</div>

<div class="section">
<h2>📷 Screenshots</h2>
<div class="content">
<div class="screenshots">
{screenshot_html if screenshot_html else '<p style="color:#888">No screenshots available.</p>'}
</div>
</div>
</div>

<div class="section">
<h2>🔴 Critical: SQL Injection</h2>
<div class="content">
<table>
<tr><th>Severity</th><th>URL</th></tr>
{sqli_html if sqli_html else '<tr><td colspan="2" style="color:#888;text-align:center">No SQL injection findings.</td></tr>'}
</table>
</div>
</div>

<div class="section">
<h2>🟠 High: XSS Vulnerabilities</h2>
<div class="content">
<table>
<tr><th>Severity</th><th>URL</th></tr>
{xss_html if xss_html else '<tr><td colspan="2" style="color:#888;text-align:center">No XSS findings.</td></tr>'}
</table>
</div>
</div>

<div class="section">
<h2>🟠 High: LFI Vulnerabilities</h2>
<div class="content">
<table>
<tr><th>Severity</th><th>URL</th></tr>
{lfi_html if lfi_html else '<tr><td colspan="2" style="color:#888;text-align:center">No LFI findings.</td></tr>'}
</table>
</div>
</div>

<div class="section">
<h2>🟠 High: Nuclei Findings</h2>
<div class="content">
<table>
<tr><th>Severity</th><th>Finding</th></tr>
{vuln_html if vuln_html else '<tr><td colspan="2" style="color:#888;text-align:center">No nuclei findings.</td></tr>'}
</table>
</div>
</div>

<div class="section">
<h2>🟡 Medium: Secrets in JS</h2>
<div class="content">
<table>
<tr><th>Severity</th><th>Secret</th></tr>
{secrets_html if secrets_html else '<tr><td colspan="2" style="color:#888;text-align:center">No secrets found in JS.</td></tr>'}
</table>
</div>
</div>

<div class="section">
<h2>🌐 Technology Stack</h2>
<div class="content">
<table>
<tr><th>Technology</th><th>Count</th></tr>
{tech_html if tech_html else '<tr><td colspan="2" style="color:#888;text-align:center">No tech detected.</td></tr>'}
</table>
</div>
</div>

<div class="section">
<h2>🏢 Live Hosts ({len(live_hosts)})</h2>
<div class="content">
<table>
<tr><th>Host</th></tr>
{live_html if live_html else '<tr><td style="color:#888;text-align:center">No live hosts.</td></tr>'}
</table>
</div>
</div>

<div class="section">
<h2>🌍 Subdomains ({len(subdomains)} found)</h2>
<div class="content" style="max-height:300px;overflow-y:auto;">
<table>
<tr><th>Subdomain</th></tr>
{sub_html if sub_html else '<tr><td style="color:#888;text-align:center">No subdomains found.</td></tr>'}
</table>
</div>
</div>

<div class="section">
<h2>📁 Raw Data</h2>
<div class="content">
<p style="color:#888">All raw tool outputs and detailed findings are available in:</p>
<pre>{out_dir}</pre>
<p style="color:#888;margin-top:10px">Open the <code>all_results/</code> directory for every tool's output including false positives.</p>
</div>
</div>

</div>

<div class="footer">
Ultimate Recon v1.0 — Generated for {target}
</div>

<script>
document.querySelectorAll('.tab').forEach(t => {{
t.addEventListener('click', function() {{
document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
this.classList.add('active');
document.querySelectorAll('.tab-content').forEach(x => x.style.display = 'none');
document.getElementById(this.dataset.tab).style.display = 'block';
}});
}});
</script>
</body>
</html>"""
