Arachnid is an open-source, modular web scanning and penetration testing assistant designed to automate reconnaissance and vulnerability discovery for security researchers and ethical hackers. Inspired by the stealth and precision of a spider, Arachnid orchestrates a suite of powerful open-source tools to perform subdomain enumeration, HTTP probing, directory brute-forcing, and more, with AI-driven insights to prioritize vulnerabilities. Built in Python, it offers a command-line interface (CLI) for ease of use, session persistence for resuming scans, and customizable configurations for flexibility.



As of July 23, 2025, Arachnid supports:
- **Tools**:
  - `subfinder.py`: Enumerates subdomains, saving to `subdomains.txt` and JSON.
  - `httpx.py`: Probes live hosts, saving URLs to `live_hosts.txt` and details to `httpx_full.json`.
  - `dirbuster.py`: Brute-forces directories, saving to `dirbuster/<netloc>.txt` and JSON.
- **Configuration**: `config.yaml` and `default_config.yaml` for output directories, timeouts, wordlists, and WAF-aware rate limits.
- **Execution Order**: `subfinder` → `httpx` → `dirbuster`, with placeholders for `paramspider`, `linkfinder`, `wafw00f`, `nuclei`, `dalfox`, `ssrfmap`, `lfimap`.
- **Data Flow**: Structured JSON outputs for AI analysis, text files for tool chaining.

The current scan all order includes subfinder, httpx, and dirbuster, with placeholders for future tools (paramspider, linkfinder, wafw00f, nuclei, dalfox, ssrfmap, lfimap). AI insights are planned via ai_analyzer.analyzer.analyze_results, leveraging JSON outputs.

The ai_analyzer/analyzer.py module, expected to be completed within 2-3 months (by October 2025), will leverage a large language model (LLM), such as a LLaMA or an API-based solution (e.g., xAI’s Grok), to analyze JSON outputs from these tools. This AI will identify patterns, prioritize vulnerabilities (e.g., exposed directories, misconfigured subdomains), and generate human-readable reports via reports/templates/report_template.md. The AI-driven ai insights command will enhance Arachnid’s utility by providing actionable recommendations, making it a powerful tool for ethical hackers


<pre>⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣠⣀⠀⠀
⢠⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⢍⣹⡀
⢸⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣯⢩⠃
⠸⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣔⣿⣿⣆⠀⠀⢀⢼⣿⡟⠀
⠀⢹⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⢷⢛⣿⣴⠒⢫⣿⠟⠀⠀
⠀⠀⢻⣆⠀⠀⠀⠀⠀⠀⠀⣀⣠⣶⢿⣋⡸⠃⠀⣿⠏⠀⠀⠀
⠀⠀⠀⢻⣆⠀⠀⣀⢤⣶⣝⣡⣶⣿⣍⣉⣀⡀⣰⡇⠀⠀⠀⠀
⠀⠀⠀⠐⢿⣧⡸⠷⠾⠋⠉⠀⠀⠀⢻⣯⣁⢀⣾⠇⠀⠀⠀⠀
⠀⠀⠀⠀⠈⠛⠂⠀⠀⠀⠀⢀⣀⣤⣾⣿⣿⣿⣿⣶⠋⢁⡆⠀
⠀⠀⠀⠀⠀⣀⣀⣠⣤⣔⣊⣁⣠⣞⣿⣿⣿⣿⢿⣿⡿⢹⠇⠀
⠀⣠⣤⣊⣉⣀⣀⣽⡿⠿⠿⠿⡛⡼⠇⠀⠈⠀⣾⠟⢁⡎⠀⠀
⡔⣋⠿⠛⠿⠛⠉⠁⠀⠀⠀⠀⠈⠁⠀⠀⠀⢘⠿⠞⢟⠁⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠀⠉⠀
  ___                __        _    __
 / _ | _______ _____/ /  ___  (_)__/ /
/ __ |/ __/ _ `/ __/ _ \/ _ \/ / _  /
/_/ |_/_/ \_,_/\__/_//_/_//_/_/\_,_/
</pre>
