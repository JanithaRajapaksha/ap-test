import os

SSID = "RPI_AP"
PASSWORD = "raspberry123"
INTERFACE = "wlan0"
STATIC_IP = "10.10.10.1/24"
DHCP_RANGE = "10.10.10.10,10.10.10.100,12h"

print("🔧 Setting up Access Point...")

# Stop services if running
os.system("sudo systemctl stop dnsmasq")
os.system("sudo systemctl stop hostapd")

# Configure static IP
dhcpcd_conf = f"""
interface {INTERFACE}
    static ip_address={STATIC_IP}
    nohook wpa_supplicant
"""
with open("/etc/dhcpcd.conf", "a") as f:
    f.write(dhcpcd_conf)
os.system("sudo service dhcpcd restart")

# Configure dnsmasq
dnsmasq_conf = f"""
interface={INTERFACE}
dhcp-range={DHCP_RANGE}
"""
with open("/etc/dnsmasq.conf", "w") as f:
    f.write(dnsmasq_conf)

# Configure hostapd
hostapd_conf = f"""
interface={INTERFACE}
driver=nl80211
ssid={SSID}
hw_mode=g
channel=6
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase={PASSWORD}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
"""
with open("/etc/hostapd/hostapd.conf", "w") as f:
    f.write(hostapd_conf)

os.system("sudo systemctl unmask hostapd")
os.system("sudo systemctl enable hostapd")
os.system("sudo systemctl enable dnsmasq")

# Start services
os.system("sudo systemctl start hostapd")
os.system("sudo systemctl start dnsmasq")

print("✅ Access Point created successfully!")
print(f"SSID: {SSID} | Password: {PASSWORD}")
