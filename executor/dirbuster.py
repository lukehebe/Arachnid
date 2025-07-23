import subprocess
import os
import json
from urllib.parse import urlparse

def save_tool_output(host, data, output_dir="output/dirbuster"):
    """
    Save tool output as JSON.
    
    :param host: Target host URL
    :param data: List of discovered URLs
    :param output_dir: Directory for output files
    :return: Path to saved JSON file
    """
    os.makedirs(output_dir, exist_ok=True)
    parsed = urlparse(host)
    safe_host = (parsed.netloc or parsed.path).replace(".", "_")
    filename = f"{safe_host}.json"
    filepath = os.path.join(output_dir, filename)
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    
    return filepath

def save_text_output(host, data, output_dir="output/dirbuster"):
    """
    Save URLs to a text file for downstream tools.
    
    :param host: Target host URL
    :param data: List of discovered URLs
    :param output_dir: Directory for output files
    :return: Path to saved text file
    """
    os.makedirs(output_dir, exist_ok=True)
    parsed = urlparse(host)
    safe_host = (parsed.netloc or parsed.path).replace(".", "_")
    filename = f"{safe_host}.txt"
    filepath = os.path.join(output_dir, filename)
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(data) + "\n")
    
    return filepath

def run(input_file="output/live_hosts.txt", output_dir="output/dirbuster", user_agent=None, config=None):
    """
    Run feroxbuster to brute-force directories on live hosts.
    
    :param input_file: Path to live hosts file (from httpx)
    :param output_dir: Directory for output files
    :param user_agent: Custom User-Agent for HTTP requests
    :param config: Configuration dictionary from config.yaml
    :return: Dictionary of host:discovered_urls
    """
    try:
 
        wordlist = config.get("dirbuster", {}).get("wordlist", "wordlists/raft-medium-directories.txt") if config else "wordlists/raft-medium-directories.txt"
        extensions = config.get("dirbuster", {}).get("extensions", "php,html,php3,htm,txt,zip") if config else "php,html,php3,htm,txt,zip"
        timeout = config.get("dirbuster", {}).get("timeout", 300) if config else 300
        rate_limit = config.get("dirbuster", {}).get("rate_limit", 10) if config else 10

        if not os.path.exists(input_file):
            print(f"[!] Live hosts file {input_file} not found.")
            return {}
        if not os.path.exists(wordlist):
            print(f"[!] Wordlist '{wordlist}' not found.")
            return {}

        # Read live hosts
        with open(input_file, "r", encoding="utf-8") as f:
            hosts = [h.strip() for h in f.read().splitlines() if h.strip()]
        
        if not hosts:
            print("[!] No live hosts found to brute-force.")
            return {}

        results = {}
        print(f"[dirbuster] Brute-forcing directories on {len(hosts)} hosts...")

        for host in hosts:
            try:
                print(f"[+] Scanning {host}...")
                cmd = [
                    "feroxbuster",
                    "-u", host,
                    "-w", wordlist,
                    "-x", extensions,
                    "-k",  # Ignore SSL errors
                    "--silent"
                ]
                if user_agent:
                    cmd.extend(["-H", f"User-Agent: {user_agent}"])
                if rate_limit:
                    cmd.extend(["--rate-limit", str(rate_limit)])

                # Run feroxbuster
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )

                if proc.returncode != 0:
                    print(f"[!] feroxbuster error for {host}: {proc.stderr.strip()}")
                    continue

                urls = []
                for line in proc.stdout.strip().splitlines():
                 
                    if line and any(code in line for code in ["200", "301", "302", "307", "401"]):
                        parts = line.split()
                        if len(parts) > 2 and parts[2].startswith("http"):
                            urls.append(parts[2])

                if urls:
                    json_path = save_tool_output(host, [{"url": url} for url in urls], output_dir)
                    txt_path = save_text_output(host, urls, output_dir)
                    results[host] = urls
                    print(f"    ├── Found {len(urls)} directories")
                    print(f"    ├── JSON output saved to: {json_path}")
                    print(f"    └── Text output saved to: {txt_path}")
                else:
                    print(f"    └── No directories found for {host}")

            except subprocess.TimeoutExpired:
                print(f"[!] Timeout while scanning {host} after {timeout} seconds.")
            except Exception as e:
                print(f"[!] Error scanning {host}: {e}")

        return results

    except Exception as e:
        print(f"[!] dirbuster execution failed: {e}")
        return {}
