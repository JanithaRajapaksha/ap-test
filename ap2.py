#!/usr/bin/env python3
# 0.4_ap_test.py — Open AP + Captive Portal (quiet NM, no 404 stack traces)
import os, sys, time, signal, subprocess, shutil, pathlib, re, threading, socket, json, urllib.parse, urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler


# from PIL import Image
# import mimetypes
from urllib.parse import urlparse


from datetime import datetime, timezone, timedelta
from dateutil import parser  # Install if needed: pip install python-dateutil on your Pi
# from PIL import Image

import runpy
from pathlib import Path


# --- URL image gating with AP-session counter ---
AP_START_COUNT = 0          # increments each time AP+portal successfully start
LAST_URL_AP_COUNT = None    # remembers when we last showed the URL image
URL_IMAGE = "https://dexmonde-uploads.s3.ap-northeast-2.amazonaws.com/record-images/f56a10cd-09d5-4777-b670-021d43fda72d.bmp?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAWFIPSYI2HU545W4P%2F20250830%2Fap-northeast-2%2Fs3%2Faws4_request&X-Amz-Date=20250830T204714Z&X-Amz-Expires=3600&X-Amz-Signature=acf6342be6f068dc84b1d7756dfdcb484ad560491ed40b12b9320d84f7dcb3e6&X-Amz-SignedHeaders=host&x-amz-checksum-mode=ENABLED&x-id=GetObject"


# ---------- Paths & globals ----------
RUN = pathlib.Path("/run")
HOSTAPD_CONF = RUN / "epaper_hostapd.conf"
HOSTAPD_PID  = RUN / "epaper_hostapd.pid"
HOSTAPD_LOG  = RUN / "epaper_hostapd.log"
DNSMASQ_CONF = RUN / "epaper_dnsmasq.conf"
DNSMASQ_PID  = RUN / "epaper_dnsmasq.pid"

HTTPD_INSTANCE = None
HTTPD_THREAD = None
HTTPD_PORT = None


# Signal from portal thread back to main loop
REJOIN_EVENT = threading.Event()


# Global AP configuration for recovery
CURRENT_AP_CONFIG = {
    'ssid': 'RoverAP',
    'country': 'LK',
    'iface': None,
    'ip_cidr': '192.168.4.1/24',
    'channel': 6
}

AWS_INIT_DONE = False  # prevents re-running the registration script
CERTS_DIR = Path("/etc/iot/certs")
REQUIRED_CERTS = ["device.crt", "device.key", "root-ca.pem"]


# ---------- Small shell helpers ----------
def _sh(cmd, timeout=None):
    # quiet shell (no stdout/stderr) with return code
    return subprocess.run(cmd, check=False, timeout=timeout,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode

def _out(cmd, timeout=None):
    # capture stdout; never prints stderr
    try:
        return subprocess.check_output(cmd, timeout=timeout, stderr=subprocess.DEVNULL).decode("utf-8","replace")
    except Exception:
        return ""

def _which(name):
    return shutil.which(name) is not None

def _which_or_die(name, apt_hint=None):
    if not _which(name):
        hint = apt_hint or name
        raise RuntimeError(f"Missing '{name}'. Install it: sudo apt-get install -y {hint}")

# ---------- Internet connectivity test ----------
def test_internet_connectivity(timeout=10):
    """Test if we have internet connectivity by trying to reach multiple hosts."""
    test_urls = [
        'http://www.google.com',
        'http://www.cloudflare.com',
        'http://1.1.1.1',
        'http://8.8.8.8'
    ]
    
    for url in test_urls:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:
                if response.getcode() == 200:
                    return True
        except Exception:
            continue
    return False

# ---------- Wi-Fi iface ----------
def detect_iface():
    txt = _out(["iw","dev"])
    m = re.search(r"Interface\s+(\S+)", txt)
    if m:
        return m.group(1)
    for cand in ("wlan0","wlp2s0","wlp3s0","wifi0"):
        if _sh(["ip","link","show",cand]) == 0:
            return cand
    return None

def kill_conflicts(ifname):
    # Stop NetworkManager/wpa_supplicant while AP is up
    _sh(["systemctl","stop","NetworkManager.service"])
    _sh(["systemctl","stop","wpa_supplicant@"+ifname+".service"])
    _sh(["systemctl","stop","wpa_supplicant.service"])
    _sh(["pkill","-f",f"wpa_supplicant.*{ifname}"])
    _sh(["pkill","hostapd"])
    _sh(["pkill","dnsmasq"])

def iface_clean_up(ifname):
    _sh(["ip","link","set",ifname,"down"])
    _sh(["ip","addr","flush","dev",ifname])
    _sh(["ip","link","set",ifname,"up"])

def iface_assign_ip(ifname, ip_cidr):
    _sh(["ip","addr","add", ip_cidr, "dev", ifname])

# ---------- AP bring-up ----------
def write_hostapd(ifname, ssid, country, channel):
    HOSTAPD_CONF.write_text(f"""interface={ifname}
driver=nl80211
ssid={ssid}
country_code={country}
ieee80211d=1

hw_mode=g
channel={channel}
ieee80211n=1
wmm_enabled=1

auth_algs=1
wpa=0
ignore_broadcast_ssid=0
""")

def write_dnsmasq(ifname, dhcp_start, dhcp_end, captive_ip="192.168.4.1"):
    DNSMASQ_CONF.write_text(f"""interface={ifname}
bind-interfaces
dhcp-range={dhcp_start},{dhcp_end},255.255.255.0,12h
dhcp-option=3,{captive_ip}
dhcp-option=6,{captive_ip}
log-queries
log-dhcp
address=/#/{captive_ip}
""")

def start_open_ap(
    ssid="RoverAP",
    country="LK",
    iface=None,
    ip_cidr="192.168.4.1/24",
    dhcp_start="192.168.4.10",
    dhcp_end="192.168.4.100",
    primary_channel=6,
) -> bool:
    global CURRENT_AP_CONFIG
    
    if os.geteuid() != 0:
        raise PermissionError("Run as root (sudo).")
    for b in ("hostapd","dnsmasq","iw","rfkill","ip"):
        _which_or_die(b)

    ifname = iface or detect_iface()
    if not ifname:
        print("No Wi-Fi interface found.")
        return False

    # Store current config for recovery
    CURRENT_AP_CONFIG.update({
        'ssid': ssid,
        'country': country,
        'iface': ifname,
        'ip_cidr': ip_cidr,
        'channel': primary_channel
    })

    # free radio & region
    _sh(["rfkill","unblock","wifi"])
    _sh(["iw","reg","set",country])

    # stop conflicts, reset iface and assign IP
    kill_conflicts(ifname)
    iface_clean_up(ifname)
    iface_assign_ip(ifname, ip_cidr)

    # try hostapd on [primary,1,6,11]
    tried = []
    for ch in (primary_channel, 1, 6, 11):
        if ch in tried:
            continue
        tried.append(ch)
        write_hostapd(ifname, ssid, country, ch)
        _sh(["rm","-f",str(HOSTAPD_PID), str(HOSTAPD_LOG)])
        rc = _sh(["hostapd","-B","-P",str(HOSTAPD_PID),"-f",str(HOSTAPD_LOG), str(HOSTAPD_CONF)])
        time.sleep(2.0)
        pid_ok = HOSTAPD_PID.exists() and HOSTAPD_PID.read_text().strip().isdigit()
        info = _out(["iw","dev",ifname,"info"])
        in_ap_mode = ("type AP" in info) or ("type __ap" in info)
        if rc == 0 and pid_ok and in_ap_mode:
            break
    else:
        tail = ""
        if HOSTAPD_LOG.exists():
            tail = HOSTAPD_LOG.read_text(errors="replace")[-2000:]
        print("hostapd failed on channels [user,1,6,11]. Tail:\n" + tail)
        return False

    # dnsmasq (with captive DNS)
    write_dnsmasq(ifname, dhcp_start, dhcp_end, captive_ip=ip_cidr.split("/")[0])
    _sh(["rm","-f",str(DNSMASQ_PID)])
    rc = _sh(["dnsmasq","-C",str(DNSMASQ_CONF), "-x", str(DNSMASQ_PID)])
    time.sleep(0.8)
    if rc != 0 or not DNSMASQ_PID.exists():
        print("dnsmasq failed to start — clients won't get IPs.")
        return False

    print(f'✓ OPEN AP "{ssid}" up on {ifname} ({ip_cidr}).')
    return True

def stop_open_ap(iface_hint="wlan0"):
    # try pidfiles first
    for pf in (HOSTAPD_PID, DNSMASQ_PID):
        try:
            if pf.exists():
                pid = pf.read_text().strip()
                if pid.isdigit():
                    subprocess.run(["kill", pid], check=False)
                pf.unlink(missing_ok=True)
        except Exception:
            pass
    # fallbacks
    subprocess.run(["pkill","hostapd"], check=False)
    subprocess.run(["pkill","dnsmasq"], check=False)
    # tidy iface
    subprocess.run(["ip","addr","flush","dev",iface_hint], check=False)
    subprocess.run(["ip","link","set",iface_hint,"down"], check=False)
    subprocess.run(["ip","link","set",iface_hint,"up"], check=False)
    print("✓ Open AP stopped")

def recover_ap_and_portal():
    """Restart the AP and captive portal with the stored configuration."""
    print("🔄 Recovering AP and captive portal...")
    
    # Start AP with stored config
    config = CURRENT_AP_CONFIG
    ok = start_open_ap(
        ssid=config['ssid'],
        country=config['country'],
        iface=config['iface'],
        ip_cidr=config['ip_cidr'],
        primary_channel=config['channel'],
        dhcp_start="192.168.4.10",
        dhcp_end="192.168.4.100"
    )
    
    if ok and not HTTPD_INSTANCE:
        start_captive_web_server()
    
    return ok

# ---------- Wi-Fi scan WITHOUT NetworkManager ----------
def scan_wifi_networks():
    """Scan using 'iw' (preferred). Returns list of dicts: ssid, signal, security."""
    nets = []
    ifname = detect_iface()
    if not ifname or not _which("iw"):
        return nets
    out = _out(["iw","dev",ifname,"scan"])
    if not out:
        return nets
    cur = {}
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("BSS "):
            if "ssid" in cur:
                if "security" not in cur:
                    cur["security"] = "none"
                nets.append(cur.copy())
            cur = {}
        elif s.startswith("SSID:"):
            ssid = s[5:].strip()
            if ssid:
                cur["ssid"] = ssid
        elif s.startswith("signal:"):
            try:
                # e.g., "signal: -55.00 dBm"
                dbm = float(s.split(":")[1].split()[0])
                sig = int(min(100, max(0, (dbm + 100) * 2)))
                cur["signal"] = sig
            except Exception:
                cur["signal"] = 0
        elif s.startswith("RSN:") or s.startswith("WPA:") or ("capability:" in s and "Privacy" in s):
            cur["security"] = "encrypted"
    if "ssid" in cur:
        if "security" not in cur:
            cur["security"] = "none"
        nets.append(cur)
    # sort strongest first
    nets.sort(key=lambda x: x.get("signal",0), reverse=True)
    return nets

def get_wifi_networks_alternative():
    """Fallback scan via iwlist (wireless-tools)."""
    nets = []
    ifname = detect_iface()
    if not ifname or not _which("iwlist"):
        return nets
    out = _out(["iwlist", ifname, "scan"])
    if not out:
        return nets
    cur = {}
    for line in out.splitlines():
        s = line.strip()
        if "Cell " in s and "Address:" in s:
            if "ssid" in cur:
                nets.append(cur.copy())
            cur = {}
        elif "ESSID:" in s:
            essid = s.split('ESSID:')[1].strip('"')
            if essid and essid != "<hidden>":
                cur["ssid"] = essid
        elif "Signal level=" in s:
            try:
                sigpart = s.split("Signal level=")[1]
                if "dBm" in sigpart:
                    dbm = float(sigpart.split(" ")[0])
                    cur["signal"] = int(min(100, max(0, (dbm + 100) * 2)))
            except Exception:
                cur["signal"] = 50
        elif "Encryption key:" in s:
            cur["security"] = "none" if "off" in s else "encrypted"
    if "ssid" in cur:
        nets.append(cur)
    nets.sort(key=lambda x: x.get("signal",0), reverse=True)
    return nets

def verify_wifi_connection(expected_ssid):
    if not _which("nmcli"):
        return False
    try:
        out = _out(["nmcli","-t","-f","ACTIVE,SSID","device","wifi"])
        for line in out.splitlines():
            if line.startswith("yes:") and expected_ssid in line:
                return True
    except Exception:
        pass
    return False

def connect_to_wifi(ssid, password, max_retries=4):
    """
    Enhanced Wi-Fi connection with retry logic and recovery.
    Returns (success: bool, message: str, should_recover: bool).
    """
    try:
        print(f"Connecting to Wi-Fi SSID '{ssid}' …")
        ifname = detect_iface() or "wlan0"

        # Stop AP components
        stop_open_ap(ifname)
        stop_captive_web_server()

        # Hand control back to NM and bring radio up
        if not _which("nmcli"):
            return False, "nmcli not available on this system.", True

        subprocess.run(["systemctl","start","NetworkManager.service"], check=False)
        time.sleep(0.5)
        subprocess.run(["nmcli","device","set",ifname,"managed","yes"], check=False)
        subprocess.run(["nmcli","radio","wifi","on"], check=False)
        time.sleep(2)

        # Clean up any existing connections
        subprocess.run(["nmcli","connection","delete", ssid], check=False)
        subprocess.run(["nmcli","connection","delete", f"{ssid}_profile"], check=False)

        # Try connecting with retries
        for attempt in range(1, max_retries + 1):
            print(f"Connection attempt {attempt}/{max_retries}")
            
            # Try direct connect first
            if password:
                rc = subprocess.run(
                    ["nmcli","device","wifi","connect", ssid, "password", password, "ifname", ifname],
                    check=False, capture_output=True, text=True
                ).returncode
            else:
                rc = subprocess.run(
                    ["nmcli","device","wifi","connect", ssid, "ifname", ifname],
                    check=False, capture_output=True, text=True
                ).returncode

            if rc == 0:
                time.sleep(5)  # Give more time for connection to stabilize
                if verify_wifi_connection(ssid):
                    # Test internet connectivity
                    print("Testing internet connectivity...")
                    if test_internet_connectivity():
                        print("✓ Connected with internet access")
                        return True, "Connected successfully with internet access.", False
                    else:
                        print("✗ Connected but no internet access")
                        return False, "Connected to Wi-Fi but no internet access detected.", True
                
            # If direct connect failed, try creating a profile
            print(f"Direct connect failed, trying profile method (attempt {attempt})")
            args = ["nmcli","connection","add","type","wifi","con-name",f"{ssid}_profile","ifname",ifname,"ssid",ssid]
            if password:
                args += ["wifi-sec.key-mgmt","wpa-psk","wifi-sec.psk", password]
            
            profile_rc = subprocess.run(args, check=False, capture_output=True, text=True).returncode
            
            if profile_rc == 0:
                up_result = subprocess.run(
                    ["nmcli","connection","up", f"{ssid}_profile"], 
                    check=False, capture_output=True, text=True
                )
                
                if up_result.returncode == 0:
                    time.sleep(5)
                    if verify_wifi_connection(ssid):
                        # Test internet connectivity
                        print("Testing internet connectivity...")
                        if test_internet_connectivity():
                            print("✓ Connected with internet access")
                            return True, "Connected successfully with internet access.", False
                        else:
                            print("✗ Connected but no internet access")
                            return False, "Connected to Wi-Fi but no internet access detected.", True
                else:
                    # Check if it's a password error
                    if "Secrets were required" in up_result.stderr or "authentication" in up_result.stderr.lower():
                        return False, "Authentication failed. Please check your password.", True

            # Clean up failed connection before retry
            subprocess.run(["nmcli","connection","delete", f"{ssid}_profile"], check=False)
            
            if attempt < max_retries:
                print(f"Attempt {attempt} failed, waiting before retry...")
                time.sleep(3)

        return False, f"Failed to connect after {max_retries} attempts. Please check signal strength and credentials.", True

    except Exception as e:
        return False, f"Exception during connection: {e}", True

# ---------- Captive portal HTTP handler ----------
class CaptivePortalHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # quiet logs
        pass

    def is_captive_portal_check(self):
        """Detect if this is a captive portal connectivity check from various devices/OS"""
        user_agent = self.headers.get('User-Agent', '').lower()
        host = self.headers.get('Host', '').lower()
        path = self.path.lower()
        
        # Common captive portal detection URLs and patterns
        captive_paths = [
            '/generate_204',           # Android, Chrome
            '/gen_204',                # Google
            '/ncsi.txt',              # Windows
            '/connecttest.txt',        # Windows 10
            '/redirect',              # Windows
            '/success.txt',           # Apple iOS/macOS (old)
            '/hotspot-detect.html',   # Apple iOS/macOS
            '/library/test/success.html', # Apple
            '/kindle-wifi/wifiredirect.html', # Amazon Kindle
            '/kindle-wifi/wifistub.html',     # Amazon Kindle
        ]
        
        captive_hosts = [
            'connectivitycheck.gstatic.com',
            'www.gstatic.com',
            'clients3.google.com',
            'www.google.com',
            'captive.apple.com',
            'www.apple.com',
            'www.msftconnecttest.com',
            'www.msftncsi.com',
            'detectportal.firefox.com',
            'nmcheck.gnome.org'
        ]
        
        # Check if this looks like a captive portal detection request
        for cp_path in captive_paths:
            if path.startswith(cp_path):
                return True
                
        for cp_host in captive_hosts:
            if cp_host in host:
                return True
                
        # Check User-Agent for known captive portal checkers
        captive_agents = [
            'captivenetworkassistant',
            'microsoft ncsi',
            'mozilla/5.0 (x11; linux x86_64) applewebkit/537.36 (khtml, like gecko) chrome/60.0.3112.32 safari/537.36',
            'dalvik/',  # Android app requests
        ]
        
        for agent in captive_agents:
            if agent in user_agent:
                return True
                
        return False

    def redirect_to_portal(self):
        """Send a redirect response to force captive portal detection"""
        try:
            self.send_response(302)
            self.send_header('Location', 'http://192.168.4.1/')
            self.send_header('Connection', 'close')
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def send_captive_response(self):
        """Send a response that triggers captive portal detection"""
        try:
            # For generate_204 requests, send a different response to trigger captive portal
            if '/generate_204' in self.path or '/gen_204' in self.path:
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', '0')
                self.send_header('Connection', 'close')
                self.end_headers()
                return
            
            # For other captive portal checks, redirect to our portal
            self.redirect_to_portal()
            
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        # Handle captive portal detection requests
        if self.is_captive_portal_check():
            print(f"Captive portal check detected: {self.path}")
            self.redirect_to_portal()
            return
            
        # Handle normal requests
        if self.path == "/" or self.path.startswith("/index"):
            self.serve_index_page()
        elif self.path == "/scan":
            self.serve_network_scan()
        else:
            # For any other path, redirect to portal (this catches all other requests)
            self.redirect_to_portal()

    def do_POST(self):
        if self.path == "/connect":
            self.handle_wifi_connect()
        else:
            self.redirect_to_portal()

    def serve_index_page(self):
        print("Serving index page – scanning Wi-Fi …")
        networks = scan_wifi_networks()
        if not networks:
            networks = get_wifi_networks_alternative()
        if not networks:
            networks = [
                {"ssid":"(No networks found)","signal":0,"security":"none"},
                {"ssid":"Manual entry required","signal":0,"security":"none"}
            ]
        parsed = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(parsed.query)
        message = q.get("message", [""])[0]
        success = q.get("success", ["false"])[0] == "true"

        html = f'''<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>E-Paper Display Wi-Fi Setup</title>
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">

<style>
:root {{
  --bg: #000000;
  --card: #000000;
  --text: #ffffff;
  --muted: #c8c8c8;
  --accent: #ffc107;
  --accent-2: #ffd54f;
  --line: #333333;
}}

body {{
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
  max-width: 500px;
  margin: 20px auto;
  padding: 20px;
  background: var(--bg);
  min-height: 100vh;
  color: var(--text);
}}

.container {{
  background: var(--card);
  padding: 25px;
  border-radius: 36px; /* rounded like a phone */
  box-shadow: none;
  border: none;
  width: 100%;
}}

h1 {{
  color: var(--text);
  text-align: center;
  margin: 6px 0 24px;
  font-size: 1.6em;
  font-weight: 700;
}}

h3 {{ color: var(--text); }}

.logo-wrap {{
  display: flex;
  justify-content: center;
  margin: 6px 0 12px;
}}

.logo {{
  width: 180px;
  max-width: 80%;
  height: auto;
  background: transparent;
}}

.network-list {{
  margin-bottom: 20px;
}}

.network-item {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  min-height: 50px;
  padding: 12px 14px;
  border: 2px solid var(--accent);
  border-radius: 8px;
  margin-bottom: 10px;
  cursor: pointer;
  transition: background .2s ease, transform .15s ease, box-shadow .2s ease;
  background: transparent;
  color: var(--text);
}}

.network-item:hover {{
  background: rgba(255, 193, 7, 0.08);
  transform: translateY(-1px);
  box-shadow: 0 6px 18px rgba(255,193,7,0.12);
}}

.network-item.selected {{
  background: rgba(255, 193, 7, 0.18);
  border-color: var(--accent);
}}

.network-item.disabled {{
  opacity: .6;
  cursor: not-allowed;
}}

.network-name {{
  font-weight: 600;
  font-size: 18px;
}}

.signal-info {{
  font-size: 13px;
  color: var(--text);
  opacity: .95;
}}

input[type="text"], input[type="password"] {{
  width: 100%;
  padding: 14px;
  margin: 10px 0;
  border: 2px solid var(--accent);
  border-radius: 8px;
  box-sizing: border-box;
  font-size: 16px;
  color: var(--text);
  background: #000000;
  transition: border-color .15s ease, box-shadow .15s ease;
}}

input[type="text"]:focus, input[type="password"]:focus {{
  outline: none;
  border-color: var(--accent-2);
  box-shadow: 0 0 0 4px rgba(255,193,7,0.15);
}}

input::placeholder {{
  color: #9f9f9f;
}}

button {{
  background: var(--accent);
  color: #111;
  padding: 14px 20px;
  border: 2px solid var(--accent);
  border-radius: 8px;
  cursor: pointer;
  width: 100%;
  font-size: 16px;
  font-weight: 800;
  transition: transform .15s ease, filter .15s ease, box-shadow .15s ease;
}}

button:hover {{
  filter: brightness(1.06);
  transform: translateY(-1px);
  box-shadow: 0 10px 24px rgba(255,193,7,0.2);
}}

.refresh-btn {{
  background: transparent;
  color: var(--text);
  padding: 8px 16px;
  border: 2px solid var(--accent);
  border-radius: 6px;
  cursor: pointer;
  font-size: 14px;
  margin-bottom: 15px;
  width: auto;
}}

.refresh-btn:hover {{
  background: rgba(255,193,7,0.08);
}}

.manual-config {{
  margin-top: 22px;
  padding-top: 22px;
  border-top: 1px solid var(--accent);
}}

.status {{
  margin-top: 18px;
  padding: 12px;
  border-radius: 8px;
  font-weight: 600;
  border: 1px solid var(--line);
  background: transparent;
}}

.success {{ border-color: #2e7d32; color: #a5d6a7; }}
.error   {{ border-color: #e53935; color: #ef9a9a; }}
.warning {{ border-color: #f57c00; color: #ffcc80; }}

.retry-info {{
  background: rgba(33,150,243,0.08);
  border: 1px solid #2196f3;
  border-radius: 6px;
  padding: 10px;
  margin: 15px 0;
  font-size: 14px;
  color: #8ec4ff;
}}

.captive-info {{
  background: rgba(76,175,80,0.10);
  border: 1px solid #2e7d32;
  border-radius: 6px;
  padding: 10px;
  margin: 15px 0;
  font-size: 14px;
  color: #b8f5c2;
}}
</style>


</head>
<body>
<div class="container">
  <!-- Centered brand logo -->
  <div class="logo-wrap">
    <img class="logo" src="img/logo.jpg" alt="otherDex">
  </div>

  <form method="post" action="/connect" id="wifiForm">
    <div class="network-list" id="networkList">
      <h3>연결가능한 WiFi:</h3>
      <!-- Network Items -->
      ''' 
        for net in networks:
            sec_icon = "📶" if (net.get("security") in (None, "", "none")) else "🔒"
            sec_txt = "Open" if sec_icon == "📶" else "Secured"
            try:
                sig = int(net.get("signal", 0))
            except:
                sig = 0
            disabled = net["ssid"].startswith("(") or net["ssid"].startswith("Manual")
            disclass = " disabled" if disabled else ""
            onclick = "" if disabled else f"onclick=\"selectNetwork('{net['ssid']}', '{net.get('security','')}')\""
            html += f'''
        <div class="network-item{disclass}" {onclick}>
        <span class="network-name">{net['ssid']}</span>
        <span class="signal-info">{sec_icon} {sig}% {sec_txt}</span>
        </div>'''
        html += f'''
</div>

    <div class="manual-config">
      <input type="text" name="ssid" id="ssid" placeholder="WiFi ID" required>
      <input type="password" name="password" id="password" placeholder="비밀번호">
      <button type="submit">WiFi 연결</button>
    </div>
  </form>

  {f'<div class="status {"success" if success else ("warning" if "internet" in message.lower() else "error")}">{message}</div>' if message else ""}
</div>


<script>
function selectNetwork(ssid, security) {{
  document.querySelectorAll('.network-item').forEach(i=>i.classList.remove('selected'));
  event.target.closest('.network-item').classList.add('selected');
  document.getElementById('ssid').value = ssid;
  document.getElementById('password').focus();
}}
function refreshNetworks() {{
  document.getElementById('loading').style.display = 'block';
  fetch('/scan').then(r=>r.json()).then(networks=> {{
    updateNetworkList(networks);
    document.getElementById('loading').style.display = 'none';
  }}).catch(_=> {{
    document.getElementById('loading').style.display = 'none';
    alert('Failed to refresh networks. Please try again.');
  }});
}}
function updateNetworkList(networks) {{
  const networkList = document.getElementById('networkList');
  let html = '<h3>Available Networks:</h3>';
  if (networks.length === 0) {{
    html += '<div class="network-item disabled"><span class="network-name">No networks found</span></div>';
  }} else {{
    networks.forEach(n => {{
      const secIcon = (!n.security || n.security==='none') ? '📶' : '🔒';
      const secTxt  = (!n.security || n.security==='none') ? 'Open' : 'Secured';
      const sig     = n.signal || 0;
      html += `
        <div class="network-item" onclick="selectNetwork('${{n.ssid}}','${{n.security||""}}')">
          <span class="network-name">${{n.ssid}}</span>
          <span class="signal-info">${{secIcon}} ${{sig}}% ${{secTxt}}</span>
        </div>`;
    }});
  }}
  networkList.innerHTML = html;
}}
</script>
</body>
</html>'''
        body = html.encode("utf-8")
        try:
            self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def serve_network_scan(self):
        nets = scan_wifi_networks()
        if not nets:
            nets = get_wifi_networks_alternative()
        body = json.dumps(nets).encode("utf-8")
        try:
            self.send_response(200)
            self.send_header("Content-Type","application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def handle_wifi_connect(self):
        try:
            length = int(self.headers.get("Content-Length","0"))
        except Exception:
            length = 0
        data = self.rfile.read(length) if length > 0 else b""
        form = urllib.parse.parse_qs(data.decode("utf-8"))
        ssid = (form.get("ssid",[""])[0] or "").strip()
        password = form.get("password",[""])[0]
        if not ssid:
            self.redirect_with_message("Please enter a network name", False)
            return
        safe_ssid = ssid.replace("'","").replace('"',"").strip()
        if not safe_ssid:
            self.redirect_with_message("Invalid network name", False)
            return

        # Redirect immediately with status while connecting in background
        self.redirect_with_message(f"Connecting to {safe_ssid}… (up to 4 attempts)", True)

        def _connect():
            success, message, should_recover = connect_to_wifi(safe_ssid, password)
            print(f"[connect] success={success}, message='{message}', should_recover={should_recover}")
            
            if success:
                # Connection successful - we're done!
                stop_captive_web_server()
                print("✓ Wi-Fi connection successful - stopping captive portal")
                REJOIN_EVENT.set()   # <<< signal main loop to resume
                
            elif should_recover:
                # Connection failed - restart AP and portal
                print("🔄 Connection failed - restarting AP and captive portal")
                time.sleep(2)  # Brief pause before recovery
                if recover_ap_and_portal():
                    print("✓ AP and captive portal recovered successfully")
                else:
                    print("✗ Failed to recover AP and captive portal")
                

        threading.Thread(target=_connect, daemon=True).start()

    def redirect_with_message(self, message, success):
        m = urllib.parse.quote(message)
        s = "true" if success else "false"
        url = f"/?message={m}&success={s}"
        try:
            self.send_response(302)
            self.send_header("Location", url)
            self.send_header("Connection", "close")
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError):
            pass

# ---------- Web server start/stop ----------
def start_captive_web_server(port_candidates=(80, 8080)):
    global HTTPD_INSTANCE, HTTPD_THREAD, HTTPD_PORT
    for p in port_candidates:
        try:
            srv = HTTPServer(("0.0.0.0", p), CaptivePortalHandler)
            try:
                srv.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except Exception:
                pass
            th = threading.Thread(target=srv.serve_forever, daemon=True)
            th.start()
            HTTPD_INSTANCE, HTTPD_THREAD, HTTPD_PORT = srv, th, p
            shown = "" if p == 80 else f":{p}"
            print(f"✓ Captive portal running: http://192.168.4.1{shown}")
            print("✓ Captive portal detection enabled - should open automatically on device connection")
            return True
        except OSError as e:
            print(f"Port {p} not available: {e}")
    print("✗ Could not bind HTTP server on 80 or 8080.")
    return False

def stop_captive_web_server():
    global HTTPD_INSTANCE, HTTPD_THREAD, HTTPD_PORT
    if HTTPD_INSTANCE:
        print("Stopping captive portal web server…")
        try:
            HTTPD_INSTANCE.shutdown()
            HTTPD_INSTANCE.server_close()
        except Exception:
            pass
        HTTPD_INSTANCE = None
        HTTPD_THREAD = None
        HTTPD_PORT = None
        print("✓ Captive portal web server stopped.")


def wifi_is_connected(ifname=None) -> bool:
    ifname = ifname or detect_iface() or "wlan0"

    # If you're running your own AP, treat it as "not connected upstream"
    try:
        if is_ap_mode(ifname):
            return False
    except Exception:
        pass

    # Prefer NetworkManager if available
    if _which("nmcli"):
        for l in _out(["nmcli", "-t", "-f", "DEVICE,STATE", "device"]).splitlines():
            if l.startswith(f"{ifname}:"):
                return l.split(":", 1)[1].strip() == "connected"

    # Fallback: has IPv4 + default route via this iface
    has_ip = "inet " in _out(["ip", "-4", "addr", "show", "dev", ifname])
    default_via_iface = ifname in _out(["ip", "route", "show", "default"])
    return has_ip and default_via_iface


def connectivity_ok() -> bool:
    # Wi-Fi must be connected and internet must be reachable
    return wifi_is_connected() and test_internet_connectivity(timeout=5)

# ---------- wifi connectivity is over on here ---------------------------------------------

# ===========================================================================================================================================================================================

#===========================================================================================================================================================================================

# ---------- Main ----------

def main():
    if os.geteuid() != 0:
        print("Please run with sudo.")
        return 1

    SSID = "RoverAP"
    COUNTRY = "LK"
    IFACE = None             # auto-detect
    CHANNEL = 6              # falls back to 1/6/11 inside start_open_ap
    IP_CIDR = "192.168.4.1/24"

    CHECK_INTERVAL = 2       # seconds between connectivity checks
    FAIL_THRESHOLD = 2       # consecutive failures before failover

    global AP_START_COUNT, LAST_URL_AP_COUNT, URL_IMAGE

    while True:
        # ---- Monitor connectivity; stay here while it's OK ----
        failures = 0
        while True:
            ok = wifi_is_connected() and test_internet_connectivity(timeout=5)
            if ok:
                print("wifi and internet is ok. Closing NetworkManager.")
                _sh(["systemctl","stop","NetworkManager"])
                # --- AWS IoT cert check & one-time registration ---
                # ensure_aws_iot_certs_once()
                # --------------------------------------------------

                time.sleep(CHECK_INTERVAL)
                failures = 0

                # Show URL image once at boot, and again ONLY when AP session counter changes
                # try:
                #     if LAST_URL_AP_COUNT is None or LAST_URL_AP_COUNT != AP_START_COUNT:
                #         local_path = fetch_image_to_file(URL_IMAGE)
                #         ok2 = show_image_only(local_path)
                #         print("URL image shown." if ok2 else "URL image show FAILED.")
                #         LAST_URL_AP_COUNT = AP_START_COUNT
                # except Exception as e:
                #     print(f"Image update error: {e}")

                continue  # keep monitoring

            # ---------- below for loss connectivity AP and hotspot flow ----------
            failures += 1
            if failures >= FAIL_THRESHOLD:
                print("✗ Connectivity lost — switching to AP mode …")
                break
            time.sleep(CHECK_INTERVAL)

        # ---- Start AP + captive portal ----
        global AP_SSID
        AP_SSID = SSID

        print("[*] Starting OPEN AP …")
        ok = start_open_ap(
            ssid=SSID, country=COUNTRY, iface=IFACE,
            ip_cidr=IP_CIDR, primary_channel=CHANNEL,
            dhcp_start="192.168.4.10", dhcp_end="192.168.4.100",
        )
        if not ok:
            print("✗ Failed to start OPEN AP (retrying in 5s)")
            time.sleep(5)
            continue

        # if not start_captive_web_server():
        #     print("✗ Failed to start captive portal web server (retrying in 5s)")
        #     stop_open_ap(IFACE or "wlan0")
        #     time.sleep(5)
        #     continue

        # >>> Increment AP session counter now that AP+portal are up
        AP_START_COUNT += 1

        # # ---- Show QR instructions on the e-paper now that AP+portal are up ----
        # try:
        #     host_ip = IP_CIDR.split("/")[0]
        #     host = host_ip + (f":{HTTPD_PORT}" if HTTPD_PORT and HTTPD_PORT != 80 else "")
        #     show_ap_qr_on_epaper(SSID, host)
        # except Exception as e:
        #     print(f"⚠️ Could not display QR on e-paper: {e}")

        # Graceful shutdown while AP is up
        def _sig(*_):
            print("\n[*] Shutting down …")
            stop_captive_web_server()
            stop_open_ap(IFACE or "wlan0")
            _sh(["systemctl","start","NetworkManager"])
            time.sleep(1)
            _sh(["rfkill","unblock","wifi"])
            sys.exit(0)

        signal.signal(signal.SIGINT, _sig)
        signal.signal(signal.SIGTERM, _sig)

        print("Waiting for Wi-Fi configuration from portal …")
        REJOIN_EVENT.clear()
        # Block here until the portal thread reports success
        while not REJOIN_EVENT.wait(timeout=1):
            pass

        print("✓ Portal signaled success — stopping AP and resuming monitoring …")
        # (connect_to_wifi already stopped AP/server, but stop again just in case)
        stop_captive_web_server()
        stop_open_ap(IFACE or "wlan0")
        REJOIN_EVENT.clear()
        time.sleep(2)  # let NetworkManager settle
# loop back and resume connectivity monitoring

    

if __name__ == "__main__":
    sys.exit(main())
