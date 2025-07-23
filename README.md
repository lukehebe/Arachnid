Arachnid is an open-source, modular web scanning and penetration testing assistant designed to automate reconnaissance and vulnerability discovery for security researchers and ethical hackers. Inspired by the stealth and precision of a spider, Arachnid orchestrates a suite of powerful open-source tools to perform subdomain enumeration, HTTP probing, directory brute-forcing, and more, with AI-driven insights to prioritize vulnerabilities. Built in Python, it offers a command-line interface (CLI) for ease of use, session persistence for resuming scans, and customizable configurations for flexibility.



As of July 23, 2025, Arachnid supports:
- **Tools**:
  - `subfinder.py`: Enumerates subdomains, saving to `subdomains.txt` and JSON.
  - `httpx.py`: Probes live hosts, saving URLs to `live_hosts.txt` and details to `httpx_full.json`.
  - `dirbuster.py`: Brute-forces directories, saving to `dirbuster/<netloc>.txt` and JSON.
- **Configuration**: `config.yaml` and `default_config.yaml` for output directories, timeouts, wordlists, and WAF-aware rate limits.
- **Execution Order**: `subfinder` → `httpx` → `dirbuster`, with placeholders for `paramspider`, `linkfinder`, `wafw00f`, `nuclei`, `dalfox`, `ssrfmap`, `lfimap`.
- **Data Flow**: Structured JSON outputs for AI analysis, text files for tool chaining.
- **File Tree**:
