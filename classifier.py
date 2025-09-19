import nmap
from scapy.all import ARP, Ether, srp
import re
import json
import os
from datetime import datetime

CACHE_FILE = "device_cache.json"

# Expanded OUI database (partial, extendable)
OUI_DB = {
    # Raspberry Pi
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",

    # ESP8266 / ESP32
    "24:6F:28": "ESP8266/ESP32",
    "7C:9E:BD": "ESP32",
    "30:AE:A4": "ESP8266",

    # Arduino
    "84:0D:8E": "Arduino",
    "90:A2:DA": "Arduino",

    # TP-Link
    "00:1A:11": "TP-Link AP",
    "F4:F2:6D": "TP-Link Router",

    # Ubiquiti
    "F4:F5:D8": "Ubiquiti AP",
    "24:A4:3C": "Ubiquiti Router",

    # Netgear
    "20:0C:C8": "Netgear Router",
    "10:DA:43": "Netgear Router",

    # Cisco
    "00:1B:54": "Cisco Router",
    "3C:CE:73": "Cisco Device",

    # Linksys
    "00:25:9C": "Linksys Router",
    "14:91:82": "Linksys Device",

    # Phones/Tablets
    "3C:5A:B4": "Samsung Phone",
    "D0:37:45": "Apple Device",
    "F8:27:93": "Huawei Device",
    "54:27:58": "Xiaomi Phone",
    "04:4B:ED": "OnePlus Device",
    "00:9A:CD": "Google Pixel",

    # Laptops / PCs
    "00:1C:BF": "Intel Laptop",
    "EC:A8:6B": "Dell Laptop",
    "40:8D:5C": "HP Laptop",
    "00:50:56": "VMware Virtual NIC",
    "00:0C:29": "VMware Host",
}

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)

def lookup_vendor(mac):
    prefix = mac.upper()[0:8]
    for known in OUI_DB:
        if prefix.startswith(known):
            return OUI_DB[known]
    return "Unknown"

def classify_device(ip, mac, cache, force=False):
    """Classify device with caching, force refresh, and confidence scoring."""
    mac = mac.upper()

    if not force and mac in cache:
        return cache[mac]["classification"], cache[mac]["confidence"]

    vendor = lookup_vendor(mac)

    # Confidence system
    confidence = 10  # base
    if vendor != "Unknown":
        confidence += 50  # strong vendor match
    elif mac[:2] in ["00", "F4", "B8"]:  # partial/generic
        confidence += 25

    scanner = nmap.PortScanner()
    try:
        scanner.scan(ip, arguments="-F")
        open_ports = scanner[ip]['tcp'].keys() if 'tcp' in scanner[ip] else []
    except:
        open_ports = []

    if "Router" in vendor or "AP" in vendor:
        classification = f"AP: {vendor}"
        confidence += 30
    elif re.search(r'ESP|Arduino|Pi', vendor, re.IGNORECASE):
        classification = f"Dev Board: {vendor}"
        confidence += 30
    elif 1883 in open_ports or 5683 in open_ports:
        classification = f"IoT Device: {vendor}"
        confidence += 20
    elif re.search(r'Apple|Samsung|Intel|Huawei|Dell|HP|Xiaomi|OnePlus|Google', vendor, re.IGNORECASE):
        classification = f"Client: {vendor}"
        confidence += 20
    else:
        classification = f"Unknown Device ({vendor})"

    confidence = min(confidence, 100)  # cap at 100

    cache[mac] = {
        "ip": ip,
        "classification": classification,
        "confidence": confidence,
        "last_seen": datetime.now().isoformat()
    }
    save_cache(cache)

    return classification, confidence

def discover_and_classify(target="192.168.1.1/24", force=False):
    """ARP scan + classify all devices with confidence scores."""
    devices = []
    cache = load_cache()

    arp = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    result = srp(ether/arp, timeout=2, verbose=0)[0]

    for sent, received in result:
        classification, confidence = classify_device(received.psrc, received.hwsrc, cache, force=force)
        devices.append({
            "ip": 

received.psrc,
            "mac": received.hwsrc,
            "classification": classification,
            "confidence": confidence
        })

    return devices
