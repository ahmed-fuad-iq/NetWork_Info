# 🛰️ Network Information Tool

A **Python GUI application (Tkinter)** that gathers and displays detailed network information — including **Public IP, IP Geolocation (via IP Info API), Local IP, MAC Address**, and **connected Wi-Fi credentials** (when available).

---

## 📦 Features

| Feature | Description |
|----------|-------------|
| 🌍 **Public IP Lookup** | Fetches your public IP using multiple APIs (`ipify`, `ident.me`, and `ipinfo.io`). |
| 🧭 **IP Info / Geolocation** | Retrieves extended information (city, region, country, ISP, ASN, timezone, etc.) using **ipinfo.io** and fallback **ip-api.com**. |
| 💻 **Local IP Detection** | Detects your active local network IP address. |
| 🔐 **MAC Address** | Shows your device’s MAC address. |
| 📶 **Wi-Fi Passwords (Optional)** | Displays saved Wi-Fi credentials (requires admin/root privileges). |
| 💾 **Save IP Info** | Export your current IP Info as a `.json` file. |
| 🧵 **Threaded Operations** | All network requests run asynchronously, so the GUI never freezes. |
| 🎨 **Modern GUI** | Clean dark-theme interface built with Tkinter. |

---

## 🖼️ Screenshot

*(Add your own screenshot here — for example:)*  
![Network Information Tool GUI](./2025-10-20 21-58-58.png)

---

## ⚙️ Installation

### 1. Clone or download the repository

git clone https://github.com/ahmed-fuad-iq/NetWork_Info.git
cd network-info-tool

pip install requests


sudo python3 main.py
