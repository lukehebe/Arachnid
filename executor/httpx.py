import subprocess
import os
import json
import re

def save_tool_output(tool_name, data, output_dir="output"):
    """
    Save tool output as JSON.
    
    :param tool_name: Name of the tool (e.g., 'httpx')
    :param data: Data to save (list of probe results)
    :param output_dir: Directory for output files
    :return: Path to saved file
    """
    os.makedirs(output_dir, exist_ok=True)
    filename = f"{tool_name}_full.json"
    filepath = os.path.join(output_dir, filename)
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    
    return filepath

def save_live_hosts(urls, output_dir="output"):
    """
    Save live host URLs to a text file for dirbuster.
    
    :param urls: List of live host URLs
    :param output_dir: Directory for output files
    :return: Path to saved file
    """
    os.makedirs(output_dir, exist_ok=True)
    txt_path = os.path.join(output_dir, "live_hosts.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(urls) + "\n")
    return txt_path

def run(input_file="output/subdomains.txt", output_dir="output", user_agent=None, config=None):
    """
    Run httpx to probe subdomains for live hosts and save results.
    
    :param input_file: Path to subdomains file (from subfinder)
    :param output_dir: Directory for output files
    :param user_agent: Custom User-Agent for HTTP requests
    :param config: Configuration dictionary from config.yaml
    :return: List of live host URLs
    """
    try:
        # Read subdomains
        if not os.path.exists(input_file):
            print(f"[!] Input file {input_file} not found.")
            return []

        with open(input_file, "r", encoding="utf-8") as f:
            subdomains = [s.strip() for s in f.read().splitlines() if s.strip()]

        if not subdomains:
            print("[!] No subdomains found to probe.")
            return []

        print(f"[httpx] Probing {len(subdomains)} subdomains...")

        # Get timeout from config or default to 300
        timeout = config.get("httpx", {}).get("timeout", 300) if config else 300

        # Build httpx command
        cmd = [
            "httpx",
            "-tls-probe",
            "-sc",  # Status code
            "-title",  # Page title
            "-cl",  # Content length
            "-td",  # Tech detection
            "-silent",
            "-json"  # Output as JSON for parsing
        ]
        if user_agent:
            cmd.extend(["-H", f"User-Agent: {user_agent}"])

        # Run httpx
        proc = subprocess.run(
            cmd,
            input="\n".join(subdomains),
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if proc.returncode != 0:
            print(f"[!] httpx error: {proc.stderr.strip()}")
            return []

        output = proc.stdout.strip().splitlines()
        results = []
        live_urls = []
        for line in output:
            try:
                data = json.loads(line)
                if data.get("status_code", 0) in (200, 301, 302, 307, 401):
                    results.append({
                        "url": data.get("url", ""),
                        "status_code": data.get("status_code", 0),
                        "title": data.get("title", ""),
                        "content_length": data.get("content_length", 0),
                        "technologies": data.get("technologies", []),
                    })
                    live_urls.append(data.get("url", ""))
            except json.JSONDecodeError:
                continue

        if not results:
            print("[!] No live hosts found.")
            return []

        output_dir = config.get("global", {}).get("output_dir", "output") if config else "output"
        json_path = save_tool_output("httpx", results, output_dir)
        txt_path = save_live_hosts(live_urls, output_dir)

        print(f"[+] httpx scan complete.")
        print(f"    ├── Found {len(live_urls)} live hosts")
        print(f"    ├── Detailed output saved to: {json_path}")
        print(f"    └── Live URLs saved to: {txt_path}")

        return live_urls

    except subprocess.TimeoutExpired:
        print(f"[!] httpx scan timed out after {timeout} seconds.")
        return []
    except Exception as e:
        print(f"[!] httpx execution failed: {e}")
        return []
