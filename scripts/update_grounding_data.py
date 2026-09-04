import json
import time
import os

# Path to the local JSON database that the scanner reads
CWE_FILE = os.path.join(os.path.dirname(__file__), "..", "codesentinel", "data", "grounding", "cwe.json")

def simulate_download():
    print("[*] [Internet Connected Machine] Connecting to MITRE CWE API feed...")
    time.sleep(1)
    print("[*] [Internet Connected Machine] Downloading latest CWE definitions...")
    time.sleep(1)
    
    # Mock data representing newly published or updated CWEs
    return {
        "CWE-918": {
            "name": "Server-Side Request Forgery (SSRF)",
            "summary": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
            "url": "https://cwe.mitre.org/data/definitions/918.html"
        },
        "CWE-1336": {
            "name": "Improper Neutralization of Special Elements Used in a Template Engine",
            "summary": "The product uses a template engine to insert or process externally-influenced input, but it does not neutralize or incorrectly neutralizes special elements that can modify the intended template logic.",
            "url": "https://cwe.mitre.org/data/definitions/1336.html"
        }
    }

def main():
    print("=== CodeSentinel Air-Gapped Updater Demo ===\n")
    
    # 1. Fetch new data (simulated)
    new_data = simulate_download()
    
    # 2. Parse and combine with the static asset structure
    print("\n[*] [Build Process] Parsing existing static CodeSentinel database...")
    try:
        with open(CWE_FILE, "r", encoding="utf-8") as f:
            cwe_db = json.load(f)
    except FileNotFoundError:
        cwe_db = {}
        
    print(f"[*] [Build Process] Found {len(cwe_db)} existing entries.")
    
    print("[*] [Build Process] Merging newly discovered vulnerabilities (e.g. CWE-918, CWE-1336)...")
    cwe_db.update(new_data)
    time.sleep(1)
    
    # 3. Compile static asset
    print("\n[*] [Build Process] Compiling updated static JSON asset...")
    with open(CWE_FILE, "w", encoding="utf-8") as f:
        json.dump(cwe_db, f, indent=2)
        
    print(f"[*] [Build Process] Success! Database now contains {len(cwe_db)} entries.")
    
    # 4. Transfer instructions
    print("\n========================================================")
    print("               READY FOR AIR-GAP TRANSFER               ")
    print("========================================================")
    print(" -> File created: codesentinel/data/grounding/cwe.json")
    print(" -> Action Required: Copy this file onto a secure USB drive")
    print(" -> Action Required: Walk to the offline CodeSentinel machine")
    print(" -> Action Required: Overwrite the existing cwe.json file")
    print("========================================================\n")
    
if __name__ == "__main__":
    main()
