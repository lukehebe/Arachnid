import subprocess
import os
import json
import re

def save_tool_output(tool_name, target, data, output_dir="output"):
    """
    Save tool output as JSON.
    
    :param tool_name: Name of the tool (e.g., 'subfinder')
    :param target: Target domain
    :param data: Data to save (list of subdomains)
    :param output_dir: Directory for output files
    :return: Path to saved file
    """
    os.makedirs(output_dir, exist_ok=True)
    safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")
    filename = f"{tool_name}_{safe_target}.json"
    filepath = os.path.join(output_dir, filename)
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    
    return filepath

def save_subdomains_txt(subdomains, output_dir="output"):
    """
    Save subdomains to a text file for httpx.
    
    :param subdomains: List of subdomains
    :param output_dir: Directory for output files
    :return: Path to saved file
    """
    os.makedirs(output_dir, exist_ok=True)
    txt_path = os.path.join(output_dir, "subdomains.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(subdomains) + "\n")
    return txt_path

def run(domain, user_agent=None, config=None):
    """
    Run subfinder against a domain and save results.
    
    :param domain: Target domain (e.g., example.com)
    :param user_agent: Custom User-Agent (ignored for subfinder)
    :param config: Configuration dictionary from config.yaml
    :return: List of discovered subdomains
    """
    try:
        # Normalize domain
        if domain.startswith(("http://", "https://")):
            domain_for_subfinder = domain.split("://", 1)[1].strip("/")
        else:
            domain_for_subfinder = domain.strip()

        print(f"[subfinder] Scanning domain: {domain_for_subfinder}")

        timeout = config.get("subfinder", {}).get("timeout", 300) if config else 300

        # Run subfinder
        cmd = ["subfinder", "-d", domain_for_subfinder, "--silent"]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if proc.returncode != 0:
            print(f"[!] subfinder error: {proc.stderr.strip()}")
            return []

        subdomains = [
            s.strip() for s in proc.stdout.strip().splitlines()
            if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$', s)
        ]

        if not subdomains:
            print("[!] No valid subdomains found.")
            return []

        output_dir = config.get("global", {}).get("output_dir", "output") if config else "output"
        json_path = save_tool_output("subfinder", domain_for_subfinder, subdomains, output_dir)
        txt_path = save_subdomains_txt(subdomains, output_dir)

        print(f"[subfinder] Found {len(subdomains)} subdomains.")
        print(f"[subfinder] Subdomains saved to {txt_path} (JSON: {json_path})")

        return subdomains

    except subprocess.TimeoutExpired:
        print(f"[!] subfinder scan timed out after {timeout} seconds.")
        return []
    except Exception as e:
        print(f"[!] subfinder execution failed: {e}")
        return []
