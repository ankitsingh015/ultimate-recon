import json
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List

class Phase3:
    NAME = "Deep Recon — Parameters, JS, Ports, Directories"

    def run(self, orch) -> dict:
        target = orch.target
        out = orch.output_dir
        raw = orch.all_results_dir
        db = orch.db
        stealth = orch.args.stealth
        config = orch.config.get("phases", {}).get("phase3", {})

        results = {
            "params": {},
            "ports": [],
            "js_secrets": [],
            "js_endpoints": [],
            "dirs_found": [],
            "hidden_params": []
        }

        urls_file = raw / "all-urls.txt"
        live_file = raw / "live-list.txt"

        if not urls_file.exists() or not urls_file.stat().st_size:
            print("  [!] No URLs file found. Using target directly.", flush=True)
            with open(urls_file, "w") as f:
                f.write(f"https://{target}\n")
        if not live_file.exists() or not live_file.stat().st_size:
            with open(live_file, "w") as f:
                f.write(f"https://{target}\n")

        gf_patterns = config.get("gf_patterns", [
            "sqli", "xss", "lfi", "ssrf", "redirect", "rce", "idor", "debug_logic", "takeovers", "secrets"
        ])

        print("  [*] Extracting parameters with gf patterns (parallel)...", flush=True)
        param_results = {}
        gf_futures = {}

        with ThreadPoolExecutor(max_workers=len(gf_patterns)) as executor:
            for pattern in gf_patterns:
                outfile = raw / f"params-{pattern}.txt"
                def make_gf_cmd(p=pattern, of=outfile):
                    return orch.run_command(
                        f"cat {urls_file} | gf {p} 2>/dev/null | uro 2>/dev/null | sort -u > {of}",
                        120
                    )
                gf_futures[executor.submit(make_gf_cmd)] = pattern

            for f in as_completed(gf_futures):
                p = gf_futures[f]
                try:
                    f.result()
                    fp = raw / f"params-{p}.txt"
                    if fp.exists() and fp.stat().st_size:
                        with open(fp) as fh:
                            lines = [l.strip() for l in fh if l.strip()]
                            results["params"][p] = lines
                            print(f"    -> {p}: {len(lines)} URLs", flush=True)
                except Exception as e:
                    print(f"    -> {p}: failed - {e}", flush=True)

        all_params = set()
        for plist in results["params"].values():
            all_params.update(plist)
        db.save_raw("params", "\n".join(sorted(all_params)), "all-params.txt")

        print("  [*] Hidden parameter discovery with Arjun...", flush=True)
        arjun_out = raw / "hidden-params.txt"
        sample_urls = list(all_params)[:20] if all_params else [f"https://{target}"]
        for url in sample_urls[:5]:
            arjun_result = orch.run_command(
                f"arjun -u {url} -oT {raw}/arjun_output.txt --passive -m GET,POST --rate-limit 10 -t 10 2>/dev/null",
                300
            )
        if arjun_out.exists():
            with open(arjun_out) as f:
                results["hidden_params"] = [l.strip() for l in f if l.strip()]
            db.save_raw("hidden_params", "\n".join(results["hidden_params"]), "hidden-params.txt")

        print("  [*] JS file discovery and analysis...", flush=True)
        js_out = raw / "js-files.txt"
        js_futures = {}

        with ThreadPoolExecutor(max_workers=4) as executor:
            js_futures[executor.submit(orch.run_command,
                f"cat {live_file} | katana -silent -d 3 -kf -jc 2>/dev/null | grep -E '\\.js$' | sort -u > {raw}/katana-js.txt", 300)] = "katana_js"

            js_futures[executor.submit(orch.run_command,
                f"cat {live_file} | subjs 2>/dev/null | sort -u > {raw}/subjs.txt", 300)] = "subjs"

            js_futures[executor.submit(orch.run_command,
                f"cat {live_file} | getJS --complete 2>/dev/null | sort -u > {raw}/getjs.txt", 300)] = "getJS"

            for f in as_completed(js_futures):
                name = js_futures[f]
                try:
                    f.result()
                    print(f"    -> {name} completed", flush=True)
                except Exception as e:
                    print(f"    -> {name}: {e}", flush=True)

        all_js = set()
        for js_src in ["katana-js.txt", "subjs.txt", "getjs.txt"]:
            fp = raw / js_src
            if fp.exists():
                with open(fp) as f:
                    for line in f:
                        line = line.strip()
                        if line and "http" in line:
                            all_js.add(line)

        all_js = sorted(all_js)
        db.save_raw("js_files", "\n".join(all_js), "all-js-files.txt")
        print(f"    -> {len(all_js)} JS files found", flush=True)

        if all_js:
            js_out_file = raw / "js-analysis.txt"
            with open(raw / "js-urls.txt", "w") as f:
                f.write("\n".join(all_js))

            print("  [*] Extracting endpoints from JS files...", flush=True)
            endpoints_result = orch.run_command(
                f"cat {raw}/js-urls.txt | head -50 | xargs -I@ -P10 bash -c 'python3 /opt/LinkFinder/linkfinder.py -i @ -o cli 2>/dev/null' 2>/dev/null | grep -oP 'https?://[^\"\\'<> ]+' | sort -u | tee {raw}/js-endpoints.txt",
                600
            )
            if (raw / "js-endpoints.txt").exists():
                with open(raw / "js-endpoints.txt") as f:
                    results["js_endpoints"] = [l.strip() for l in f if l.strip()]
                db.save_raw("js_endpoints", "\n".join(results["js_endpoints"]), "js-endpoints.txt")
                print(f"    -> {len(results['js_endpoints'])} endpoints from JS", flush=True)

            print("  [*] Extracting secrets from JS files...", flush=True)
            secrets_result = orch.run_command(
                f"cat {raw}/js-urls.txt | head -50 | xargs -I@ -P5 python3 /opt/SecretFinder/SecretFinder.py -i @ -o cli 2>/dev/null | grep -iE '(api.?key|secret|token|password|aws|bucket|slack|firebase|jwt|heroku)' | sort -u | tee {raw}/js-secrets.txt",
                600
            )
            if (raw / "js-secrets.txt").exists():
                with open(raw / "js-secrets.txt") as f:
                    results["js_secrets"] = [l.strip() for l in f if l.strip() and l.strip()[:1].isalpha()]
                db.save_raw("js_secrets", "\n".join(results["js_secrets"]), "js-secrets.txt")
                print(f"    -> {len(results['js_secrets'])} potential secrets", flush=True)

            print("  [*] Running nuclei on JS files...", flush=True)
            nuclei_js = orch.run_command(
                f"cat {raw}/js-urls.txt | nuclei -silent -t ~/nuclei-templates/http/exposures/ -c 30 2>/dev/null | tee {raw}/nuclei-js.txt",
                600
            )

        print("  [*] Port scanning live hosts...", flush=True)
        if not stealth:
            ports_out = raw / "open-ports.txt"
            port_result = orch.run_command(
                f"cat {live_file} | naabu -silent -c {orch.args.threads} -o {raw}/naabu-ports.txt 2>/dev/null",
                600
            )
            if (raw / "naabu-ports.txt").exists():
                with open(raw / "naabu-ports.txt") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            parts = line.split(":")
                            if len(parts) == 2:
                                results["ports"].append({"ip": parts[0], "port": int(parts[1])})
                db.save_raw("ports", "\n".join([f"{p['ip']}:{p['port']}" for p in results["ports"]]), "open-ports.txt")
                print(f"    -> {len(results['ports'])} open ports found", flush=True)

        print("  [*] Directory brute-forcing (top hosts)...", flush=True)
        if not stealth:
            dirs_out = raw / "dirs-found.txt"
            dir_result = orch.run_command(
                f"cat {live_file} | head -5 | xargs -I@ dirsearch -u @ -w /usr/share/seclists/Discovery/Web-Content/common.txt " 
                f"-e php,asp,aspx,jsp,html,txt -t 20 --random-agent --exclude-status=404,403 "
                f"--simple-report={raw}/dirsearch-report.txt 2>/dev/null",
                600
            )
            if (raw / "dirsearch-report.txt").exists():
                with open(raw / "dirsearch-report.txt") as f:
                    results["dirs_found"] = [l.strip() for l in f if l.strip()]

        print("  [*] Sensitive file discovery...", flush=True)
        sens_result = orch.run_command(
            f"cat {urls_file} 2>/dev/null | grep -E '\\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|env|git|svn|p12|pem|key|crt|csr|sh|py|java|class|war|ear|sqlitedb|sqlite3|accdb|mdb|gitignore|ini|conf|properties|plist|cfg)$' "
            f"| sort -u | tee {raw}/sensitive-files.txt",
            120
        )
        sens_files = []
        if (raw / "sensitive-files.txt").exists():
            with open(raw / "sensitive-files.txt") as f:
                sens_files = [l.strip() for l in f if l.strip()]
            db.save_raw("sensitive_files", "\n".join(sens_files), "sensitive-files.txt")
            print(f"    -> {len(sens_files)} potentially sensitive files", flush=True)

        print("  [*] Cloud asset enumeration...", flush=True)
        cloud_result = orch.run_command(
            f"cloud_enum -k {target} 2>/dev/null | tee {raw}/cloud-assets.txt", 300
        )

        print("  [*] Exposed .git detection...", flush=True)
        git_result = orch.run_command(
            f"cat {live_file} | head -10 | httpx -silent -path /.git/config -mc 200 -ms '[core]' 2>/dev/null | tee {raw}/git-leaks.txt",
            300
        )

        results["summary"] = {
            "param_categories": len(results["params"]),
            "total_param_urls": sum(len(v) for v in results["params"].values()),
            "js_files": len(all_js),
            "js_secrets": len(results["js_secrets"]),
            "open_ports": len(results["ports"]),
            "sensitive_files": len(sens_files)
        }

        nuclei_file = raw / "nuclei-exposures.txt"
        print("  [*] Running nuclei exposures scanning...", flush=True)
        nuclei_result = orch.run_command(
            f"cat {live_file} | nuclei -silent -t ~/nuclei-templates/http/exposures/ -c {orch.args.threads} "
            f"-bs 50 -o {nuclei_file} 2>/dev/null",
            600
        )

        return results

