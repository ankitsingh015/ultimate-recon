import os
import json
import subprocess
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List

class Phase1:
    NAME = "Asset Discovery — Subdomains, IPs, ASN"

    def run(self, orch) -> dict:
        target = orch.target
        out = orch.output_dir
        raw = orch.all_results_dir
        db = orch.db
        config = orch.config.get("phases", {}).get("phase1", {})
        api_keys = orch.api_keys
        stealth = orch.args.stealth

        target_id = 1
        all_subdomains = set()
        all_ips = set()
        all_asn = set()
        results = {}

        def run_tool(name: str, cmd: str, outfile: str = None) -> List[str]:
            result = orch.run_command(cmd, timeout=900)
            if outfile:
                outpath = raw / outfile
                with open(outpath, "w") as f:
                    f.write(result.stdout)
                    if result.stderr:
                        f.write("\n# STDERR:\n" + result.stderr)
            lines = [l.strip() for l in result.stdout.split("\n") if l.strip()]
            orch.update_progress(1, total_tasks, completed[0], f"{name}: {len(lines)}")
            completed[0] += 1
            return lines

        total_tasks = 22 if not stealth else 14
        completed = [0]
        subdomain_file = raw / "all-subdomains.txt"

        print(f"\n  Launching {total_tasks} parallel tasks...\n", flush=True)

        with ThreadPoolExecutor(max_workers=min(orch.args.threads, total_tasks)) as executor:
            futures = {}

            futures[executor.submit(run_tool, "subfinder",
                f"subfinder -d {target} -all -recursive -o {raw}/subfinder.txt 2>/dev/null && cat {raw}/subfinder.txt 2>/dev/null", "subfinder.txt")] = "subfinder"

            futures[executor.submit(run_tool, "assetfinder",
                f"assetfinder --subs-only {target} 2>/dev/null | tee {raw}/assetfinder.txt", "assetfinder.txt")] = "assetfinder"

            futures[executor.submit(run_tool, "findomain",
                f"findomain -t {target} -q 2>/dev/null | tee {raw}/findomain.txt", "findomain.txt")] = "findomain"

            futures[executor.submit(run_tool, "amass_passive",
                f"amass enum -passive -d {target} -timeout 5 -o {raw}/amass_passive.txt 2>/dev/null && cat {raw}/amass_passive.txt 2>/dev/null", "amass_passive.txt")] = "amass_passive"

            futures[executor.submit(run_tool, "crt.sh",
                f"curl -s 'https://crt.sh/?q=%25.{target}&output=json' 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | grep -Po '(\\w+\\.\\w+\\.\\w+)$' | sort -u | tee {raw}/crtsh.txt", "crtsh.txt")] = "crtsh"

            futures[executor.submit(run_tool, "wayback",
                f"curl -s 'http://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=text&fl=original&collapse=urlkey' 2>/dev/null | sort -u | sed -e 's_https*://__' -e 's/\\/.*//' -e 's/:.*//' -e 's/^www\\.//' | sort -u | tee {raw}/wayback.txt", "wayback.txt")] = "wayback"

            futures[executor.submit(run_tool, "urlscan",
                f"curl -s 'https://urlscan.io/api/v1/search/?q=domain:{target}&size=100' 2>/dev/null | jq -r '.results[].page.domain' 2>/dev/null | sort -u | tee {raw}/urlscan.txt", "urlscan.txt")] = "urlscan"

            futures[executor.submit(run_tool, "hackertarget",
                f"curl -s 'https://api.hackertarget.com/hostsearch/?q={target}' 2>/dev/null | cut -d',' -f1 | sort -u | tee {raw}/hackertarget.txt", "hackertarget.txt")] = "hackertarget"

            cc_indexes = "CC-MAIN-2025-04 CC-MAIN-2024-42 CC-MAIN-2024-22 CC-MAIN-2024-18 CC-MAIN-2024-10".split()
            cc_cmds = " && ".join(
                f"curl -s 'https://index.commoncrawl.org/{idx}-index?url=*.{target}&output=json' 2>/dev/null | jq -r '.url' 2>/dev/null"
                for idx in cc_indexes
            )
            futures[executor.submit(run_tool, "commoncrawl",
                f"({cc_cmds}) 2>/dev/null | sed -e 's_https*://__' -e 's/\\/.*//g' | sort -u | tee {raw}/commoncrawl.txt", "commoncrawl.txt")] = "commoncrawl"

            if api_keys.get("virustotal"):
                futures[executor.submit(run_tool, "virustotal",
                    f"curl -s 'https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_keys['virustotal']}&domain={target}' 2>/dev/null | jq -r '.domain_siblings[]' 2>/dev/null | sort -u | tee {raw}/virustotal.txt", "virustotal.txt")] = "virustotal"

            if api_keys.get("github"):
                futures[executor.submit(run_tool, "github",
                    f"github-subdomains -d {target} -t {api_keys['github']} 2>/dev/null | sort -u | tee {raw}/github.txt", "github.txt")] = "github"

            if api_keys.get("shodan"):
                futures[executor.submit(run_tool, "shosubgo",
                    f"shosubgo -d {target} -s {api_keys['shodan']} 2>/dev/null | tee {raw}/shosubgo.txt", "shosubgo.txt")] = "shosubgo"
                futures[executor.submit(run_tool, "shodan_domain",
                    f"shodan domain {target} 2>/dev/null | awk '{{print $3}}' | sort -u | tee {raw}/shodan_domain.txt", "shodan_domain.txt")] = "shodan_domain"

            if api_keys.get("chaos"):
                futures[executor.submit(run_tool, "chaos",
                    f"chaos -d {target} -silent 2>/dev/null | tee {raw}/chaos.txt", "chaos.txt")] = "chaos"

            if api_keys.get("securitytrails"):
                futures[executor.submit(run_tool, "haktrails",
                    f"haktrails {target} 2>/dev/null | sort -u | tee {raw}/haktrails.txt", "haktrails.txt")] = "haktrails"

            futures[executor.submit(run_tool, "dnsrecon",
                f"dnsrecon -d {target} -t std 2>/dev/null | grep -oP '([a-zA-Z0-9.-]+\\.{target})' | sort -u | tee {raw}/dnsrecon.txt", "dnsrecon.txt")] = "dnsrecon"

            for future in as_completed(futures):
                name = futures[future]
                try:
                    lines = future.result()
                    all_subdomains.update(lines)
                    if lines:
                        orch.update_progress(1, total_tasks, completed[0], f"{name}: {len(lines)}")
                except Exception as e:
                    orch.update_progress(1, total_tasks, completed[0], f"{name}: ERROR")

        orch.update_progress(1, total_tasks, total_tasks, "All subdomain tools completed")

        all_subs = sorted(all_subdomains)
        db.save_raw("subdomains", "\n".join(all_subs), "all-subdomains.txt")
        db.add_subdomains(target_id, all_subs, "all_sources")

        results["subdomains"] = all_subs
        results["subdomain_count"] = len(all_subs)

        if not stealth:
            print("  [*] Running permutations + brute-force (parallel)...", flush=True)
            perms_out = raw / "permutations.txt"
            brute_out = raw / "bruteforce.txt"
            resolved_out = raw / "resolved_subdomains.txt"

            perm_futures = {}
            with ThreadPoolExecutor(max_workers=3) as pexec:
                perm_futures[pexec.submit(orch.run_command,
                    f"cat {subdomain_file} 2>/dev/null | alterx -enrich 2>/dev/null | dnsx -silent -a -resp-only -r wordlists/resolvers.txt 2>/dev/null | sort -u | tee {perms_out}", 600)] = "permutations"

                perm_futures[pexec.submit(orch.run_command,
                    f"cat {subdomain_file} 2>/dev/null | shuffledns -d {target} -r wordlists/resolvers.txt -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -silent 2>/dev/null | sort -u | tee {brute_out}", 600)] = "bruteforce"

                for pf in as_completed(perm_futures):
                    name = perm_futures[pf]
                    try:
                        r = pf.result()
                        if r.stdout:
                            new_lines = [l.strip() for l in r.stdout.split("\n") if l.strip()]
                            all_subdomains.update(new_lines)
                            db.append_raw("subdomains", r.stdout, "all-subdomains.txt")
                            print(f"    -> {name}: {len(new_lines)} new", flush=True)
                    except Exception:
                        print(f"    -> {name}: failed", flush=True)

            print("  [*] Resolving subdomains...", flush=True)
            resolve_result = orch.run_command(
                f"cat {raw}/all-subdomains.txt 2>/dev/null | sort -u | dnsx -silent -a -resp-only -r wordlists/resolvers.txt 2>/dev/null | sort -u | tee {resolved_out}",
                300
            )

        print("  [*] Running ASN + IP discovery...", flush=True)
        asn_out = raw / "asn-ips.txt"
        asn_result = orch.run_command(
            f"asnmap -d {target} 2>/dev/null | dnsx -silent -resp-only -r wordlists/resolvers.txt 2>/dev/null | sort -u | tee {asn_out}",
            300
        )
        if asn_result.stdout:
            asn_ips = [l.strip() for l in asn_result.stdout.split("\n") if l.strip()]
            all_ips.update(asn_ips)
            results["ips"] = list(all_ips)
            db.save_raw("ips", "\n".join(sorted(all_ips)), "all-ips.txt")

        ip_out = raw / "all-ips-extracted.txt"
        ip_cmds = [
            f"curl -s 'https://otx.alienvault.com/api/v1/indicators/hostname/{target}/url_list?limit=500&page=1' 2>/dev/null | jq -r '.url_list[]?.result?.urlworker?.ip // empty' 2>/dev/null | grep -Eo '([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}' >> {ip_out}",
        ]
        with ThreadPoolExecutor(max_workers=2) as iexec:
            ipseeds = {}
            for icmd in ip_cmds:
                ipseeds[iexec.submit(orch.run_command, icmd, 120)] = "alienvault"

            if api_keys.get("shodan"):
                ipseeds[iexec.submit(orch.run_command,
                    f"shodan search Ssl.cert.subject.CN:\"{target}\" 200 --fields ip_str 2>/dev/null >> {ip_out}", 300)] = "shodan_search"

            for iseed in as_completed(ipseeds):
                pass

        if ip_out.exists():
            with open(ip_out) as f:
                extra_ips = [l.strip() for l in f if l.strip()]
                all_ips.update(extra_ips)
            db.save_raw("ips_extracted", "\n".join(sorted(all_ips)), "all-ips-extracted.txt")

        results["ips"] = list(all_ips)
        results["ip_count"] = len(all_ips)

        if api_keys.get("shodan") and not stealth:
            print("  [*] Running Shodan-powered URL discovery...", flush=True)
            shodan_urls = orch.run_command(
                f"shodan domain {target} 2>/dev/null | awk '{{print $3}}' | httpx-toolkit -silent 2>/dev/null | nuclei -silent -s critical,high,medium 2>/dev/null | tee {raw}/shodan-nuclei.txt",
                600
            )

        final_subs = sorted(all_subdomains)
        db.save_raw("subdomains_final", "\n".join(final_subs), "final-subdomains.txt")

        results["summary"] = {
            "subdomains": len(all_subdomains),
            "ips": len(all_ips),
            "asn_ranges": len(all_asn)
        }

        return results

