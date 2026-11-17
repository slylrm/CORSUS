# Security Tools Arsenal

WeppenTest remains AI-free. Existing scan lifecycle wrappers remain the primary scan integration; optional tools are discoverable through `GET /api/v1/tools/arsenal`. Installation is not required to start the app. The endpoint reports local availability and metadata without starting scans. Tool versions below are a research snapshot (17 Nov 2026); release pages are authoritative because upstream versions change.

## TLS tools

| Tool | Version snapshot | Install and platform notes | Example / machine output | Official docs |
|---|---|---|---|---|
| testssl.sh | 3.2.5 stable | Bash + OpenSSL; native Linux/macOS, Windows via WSL or supported Docker image | `./testssl.sh --fast --jsonfile tls.json example.test:443`; JSON, CSV, HTML | [Usage](https://testssl.sh/), [releases](https://github.com/testssl/testssl.sh/releases) |
| SSLyze | 6.3.1 | `python -m pip install sslyze`; Python 3.10+ and Windows/Linux/macOS wheels | `python -m sslyze example.test --json_out=tls.json`; JSON schema documented | [CLI](https://nabla-c0d3.github.io/sslyze/), [JSON](https://github.com/nabla-c0d3/sslyze/blob/release/docs/documentation/json-output.html), [releases](https://github.com/nabla-c0d3/sslyze/releases) |
| sslscan | 2.2.4 | Prebuilt releases; Linux/macOS/Windows builds; Docker available | `sslscan --no-colour --json=scan.json example.test:443`; JSON/XML/text | [README](https://github.com/rbsec/sslscan), [releases](https://github.com/rbsec/sslscan/releases) |

testssl.sh uses Bash and OpenSSL compatibility; Windows users should choose WSL or its documented container route. SSLyze is the easiest direct Windows option. sslscan Windows behavior depends on the release asset selected.

## Web and network tools

| Tool | Release/install reference | Safe, bounded example and output | Integration |
|---|---|---|---|
| Nuclei | 3.11.1; [releases](https://github.com/projectdiscovery/nuclei/releases), Go install or binaries | `nuclei -u http://127.0.0.1:8000 -severity low,medium -rl 5 -jsonl -o nuclei.jsonl`; JSONL | Existing wrapper; inventory and bounded runner |
| OWASP ZAP | 2.17.0; [releases](https://github.com/zaproxy/zaproxy/releases), official Docker image | Daemon API; reports JSON/XML/HTML/Markdown. Keep API key and reachable network scoped. | Existing service/API wrapper, Compose `scanners` profile |
| SQLMap | 1.10.11; [source/history](https://github.com/sqlmapproject/sqlmap), Python source checkout | `sqlmap -u http://127.0.0.1/item?id=1 --batch --risk=1 --level=1 --smart`; text/CSV/JSON/SQLite outputs | Existing wrapper; low risk defaults |
| ffuf | [releases](https://github.com/ffuf/ffuf/releases), Go install; Windows binaries available | `ffuf -u http://127.0.0.1/FUZZ -w wordlist.txt -rate 5 -of json -o ffuf.json`; JSON/CSV/ejson/HTML/Markdown | Inventory only; execution needs explicit wordlist and scope configuration |
| httpx (ProjectDiscovery) | 1.12.0; [releases](https://github.com/projectdiscovery/httpx/releases), Go install | `httpx -u http://127.0.0.1 -json -status-code -title -rate-limit 5`; JSONL | Inventory; avoid confusion with Python `httpx` package executable |
| Nikto | 2.6.1; [source/releases](https://github.com/sullo/nikto) | `nikto -host http://127.0.0.1:8000 -Format json -output nikto.json`; JSON/XML/CSV/HTML/text | Existing wrapper; Perl required for source on Windows |
| Wapiti | 3.3.2; [releases](https://github.com/wapiti-scanner/wapiti/releases), `pip install wapiti3` | `wapiti -u http://127.0.0.1:8000 -f json -o wapiti.json --scope url`; JSON/HTML/XML/TXT | Existing wrapper |
| Dalfox | 3.3.0; [releases](https://github.com/hahwul/dalfox/releases), Go install/binaries | `dalfox url 'http://127.0.0.1/?q=test' --format json --silence`; JSON/text | Inventory; explicit local-only profile |
| Nmap | 7.993; [changelog](https://nmap.org/changelog.html), official Windows installer or Linux packages | `nmap -T2 --top-ports 100 -oX nmap.xml 127.0.0.1`; XML/grepable/normal | Existing wrapper |

Versions were checked against official release pages and upstream changelogs on 17 Nov 2026. Projects without a stable release label use a rolling/release-page marker in the manager; local versions should be confirmed with each tool's version flag. Availability may depend on OS, Perl, Go, Python, or container runtime. Do not expose scanner services publicly.

## Manager contract

The inventory contains tool name, version/reference, install status, executable path, supported OSes, CLI argument metadata, defaults, output formats, timeout, Docker image and official URLs. `/api/v1/tools/arsenal/{name}/run` accepts a target plus a timeout option only. It creates an argv list, sets `shell=False`, caps timeout at 900 seconds, kills its child on timeout/cancellation, uses conservative profiles, and currently only permits localhost. This explicit manager endpoint does not create a persisted scan/report record. ffuf, ZAP, LLM and browser entries remain inventory-only. Existing scan lifecycle wrappers and `/api/v1/tools` remain available.

Native output is returned in a common envelope (`tool`, `target`, `status`, `exit_code`, `output`); JSON is parsed when stdout is a single JSON document. JSONL/mixed native output remains text pending per-tool parsers. Process timeout returns `status: timeout`.

Run active scanners only against systems within written authorization and scope. Never enable destructive SQLMap options (`--dump`, `--os-shell`, `--file-write`, `--file-dest`) as generic profiles. Nuclei templates and scanner releases should be kept current and reviewed.
