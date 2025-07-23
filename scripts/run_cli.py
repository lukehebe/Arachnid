import os
import sys
import yaml
from urllib.parse import urlparse

# Add parent directory to sys.path for module imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from datastore.context import set_target_url, get_target_url, set_session_data, get_session_data
from datastore.persistence import save_session, load_session
from ai_analyzer.analyzer import analyze_results
from executor import (
    dalfox, ssrfmap, nuclei, httpx, lfimap, paramspider,
    linkfinder, wafw00f, subfinder, dirbuster,
)

# Load configuration
def load_config():
    config_path = os.path.join(os.path.dirname(__file__), '../config/config.yaml')
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        print("[!] Config file not found. Using defaults.")
        return {}

CONFIG = load_config()

BANNER = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣠⣀⠀⠀
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

  "The supreme art of war is to subdue the enemy without fighting."
                              — Sun Tzu
"""

CATEGORY_SCANNERS = {
    "xss": [dalfox.run, paramspider.run, linkfinder.run],
    "ssrf": [ssrfmap.run],
    "lfi": [lfimap.run],
    "recon": [
        subfinder.run,
        httpx.run,
        dirbuster.run,
        paramspider.run,
        linkfinder.run,
        wafw00f.run,
    ],
    "all": [
        subfinder.run,
        httpx.run,
        dirbuster.run,
        paramspider.run,
        linkfinder.run,
        wafw00f.run,
        nuclei.run,
        dalfox.run,
        ssrfmap.run,
        lfimap.run,
    ],
}

def print_help():
    print("""
Commands:
  seturl <url>            Set the target URL or domain (e.g. example.com)
  setua <user-agent>      Set a custom User-Agent header for HTTP requests
  scan all                Run all scanners
  scan xss                XSS-focused scanning
  scan ssrf               SSRF scanning
  scan lfi                LFI scanning
  scan recon              Subdomain + endpoint discovery
  ai insights             Analyze scan results and show key vulnerabilities
  save <name>             Save current session
  load <name>             Load a saved session
  clear                   Clear current session data
  help                    Show this help menu
  exit                    Exit Arachnid
""")

def normalize_domain(input_str):
    """
    Extract bare domain (no protocol).
    """
    if "://" in input_str:
        parsed = urlparse(input_str)
        return parsed.netloc or parsed.path  # Fallback to path if netloc is empty
    return input_str.strip()

def normalize_url(input_str):
    """
    Ensure URL has protocol, default https://
    """
    input_str = input_str.strip()
    if not input_str.startswith(("http://", "https://")):
        return "https://" + input_str
    return input_str

def scan_category(category, input_target, user_agent=None, config=None):
    if category not in CATEGORY_SCANNERS:
        print(f"[!] Unknown category '{category}'. Type 'help' to see options.")
        return {}

    print(f"[+] Starting scan: {category.upper()}")
    results = {}

    domain = normalize_domain(input_target)
    url = normalize_url(input_target)

    for scanner in CATEGORY_SCANNERS[category]:
        try:
            name = scanner.__module__.split('.')[-1]
            print(f"[>] Running {name}...")

           
            if name in ['subfinder', 'paramspider', 'linkfinder']:
                results[name] = scanner(domain, config=config)
       
            else:
                results[name] = scanner(url, user_agent=user_agent, config=config)
        except Exception as e:
            print(f"[!] {name} failed: {e}")
  
    print(f"[+] {category.upper()} scan completed.")
    for name, data in results.items():
        count = len(data) if isinstance(data, list) else "Processed"
        print(f"    ├── {name}: {count} items")
    return results

def main():
    print(BANNER)
    print("Welcome to Arachnid — The Enhanced Web Scanner")
    print("Type 'help' to see options.\n")

    # Load session data from context
    session_data = get_session_data() or {}
    custom_user_agent = None

    while True:
        try:
            cmd = input("arachnid > ").strip()

            if not cmd:
                continue

            cmd_lower = cmd.lower()

            if cmd_lower == "help":
                print_help()

            elif cmd_lower.startswith("seturl"):
                parts = cmd.split(maxsplit=1)
                if len(parts) == 2:
                    set_target_url(parts[1])
                    print(f"[+] Target URL set to: {parts[1]}")
                else:
                    print("Usage: seturl <url>")

            elif cmd_lower.startswith("setua"):
                parts = cmd.split(maxsplit=1)
                if len(parts) == 2:
                    custom_user_agent = parts[1]
                    print(f"[+] Custom User-Agent set to: {custom_user_agent}")
                else:
                    print("Usage: setua <user-agent>")

            elif cmd_lower.startswith("scan"):
                parts = cmd_lower.split()
                if len(parts) != 2:
                    print("Usage: scan <category>")
                    continue
                input_target = get_target_url()
                if not input_target:
                    print("[!] No URL set. Use 'seturl <url>' first.")
                    continue
                category = parts[1]
                results = scan_category(category, input_target, user_agent=custom_user_agent, config=CONFIG)
                session_data.update(results)
                set_session_data(session_data)  # Persist session data

            elif cmd_lower == "ai insights":
                if not session_data:
                    print("[!] No scan results to analyze.")
                    continue
                print("[+] Analyzing results with AI...\n")
                suggestions = analyze_results(session_data)
                print("\n=== AI-Generated Insights ===\n")
                print(suggestions)

            elif cmd_lower.startswith("save"):
                parts = cmd.split(maxsplit=1)
                if len(parts) == 2:
                    save_session(parts[1], session_data)
                    print(f"[+] Session saved as '{parts[1]}'")
                else:
                    print("Usage: save <session_name>")

            elif cmd_lower.startswith("load"):
                parts = cmd.split(maxsplit=1)
                if len(parts) == 2:
                    session_data = load_session(parts[1])
                    set_session_data(session_data)
                    print(f"[+] Session '{parts[1]}' loaded.")
                else:
                    print("Usage: load <session_name>")

            elif cmd_lower == "clear":
                session_data = {}
                set_session_data(session_data)
                print("[+] Session data cleared.")

            elif cmd_lower in ("exit", "quit"):
                print("Exiting Arachnid. Stay stealthy.")
                break

            else:
                print("[!] Unknown command. Type 'help' to see options.")

        except KeyboardInterrupt:
            print("\n[!] Interrupted. Use 'exit' to quit.")
        except Exception as e:
            print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
