# Tool Manager and CLI arguments

Inspect the manager with `GET /api/v1/tools/arsenal`; see `POST /api/v1/tools/arsenal/{tool}/run` for the narrow localhost execution interface. Neither endpoint accepts a raw command string. The process boundary uses argument arrays (`shell=False`), a 900-second hard timeout ceiling, and per-tool fixed safe defaults.

| Tool | Common documented arguments | Default/output |
|---|---|---|
| testssl.sh | `--fast`, `--severity`, `--jsonfile` | fast; JSON/CSV/HTML |
| SSLyze | `--regular`, `--json_out`, `--mozilla_config` | regular; JSON |
| sslscan | `--no-colour`, `--xml`, `--json` | no colour; JSON/XML |
| Nuclei | `-u`, `-severity`, `-rl`, `-timeout`, `-retries`, `-jsonl` | low impact template scan, rate 5; JSONL |
| ZAP | daemon options and API endpoints | passive by default in existing integration; API report formats |
| SQLMap | `-u`, `--batch`, `--risk`, `--level`, `--output-dir` | risk 1/level 1; no extraction or takeover |
| ffuf | `-u`, `-w`, `-rate`, `-maxtime`, `-of`, `-o` | rate 5; JSON |
| PD httpx | `-u`, `-json`, `-status-code`, `-title`, `-rate-limit` | rate 5; JSONL |
| Nikto | `-host`, `-timeout`, `-Format`, `-output` | JSON |
| Wapiti | `-u`, `-f`, `-o`, `--max-scan-time`, `--scope` | URL scope; JSON |
| Dalfox | `url`, `--format`, `--output`, `--silence` | JSON |
| Nmap | `-T2`, `--top-ports`, `-sV`, `-oX` | timing T2, top 100; XML |
| Garak | `--model_type`, `--model_name`, `--probes`, `--report_prefix` | explicit model/probe configuration required |
| PyRIT | subcommands; consult `pyrit --help` | isolated environment/database |
| Promptfoo | `eval`, `redteam`, `--output` | explicit config/provider required |
| Playwright | browser install/test runner options | isolated project dependency |
| Chrome | `--headless`, `--remote-debugging-port`, `--user-data-dir` | dedicated profile; never attach to a personal session |

Argument interfaces vary by release. Verify with each official help page/release before adding a runner profile. Official references: [testssl](https://testssl.sh/), [SSLyze](https://nabla-c0d3.github.io/sslyze/), [sslscan](https://github.com/rbsec/sslscan), [Nuclei](https://docs.projectdiscovery.io/tools/nuclei/overview), [ZAP](https://www.zaproxy.org/docs/), [SQLMap](https://github.com/sqlmapproject/sqlmap/wiki/Usage), [ffuf](https://github.com/ffuf/ffuf), [httpx](https://docs.projectdiscovery.io/tools/httpx/usage), [Nikto](https://github.com/sullo/nikto/wiki), [Wapiti](https://wapiti-scanner.github.io/), [Dalfox](https://dalfox.hahwul.com/), [Nmap](https://nmap.org/book/man.html).
