# main.py
# Edited by assistant: added improved Public IP lookup + IP info API + "Get IP Info" and "Save IP Info" functionality
# Original file referenced: :contentReference[oaicite:1]{index=1}

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import requests
import subprocess
import re
import platform
import uuid
import sys
import os
import threading
import json

class NetworkInfoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Information Tool")
        self.root.geometry("820x520")
        self.root.configure(bg='black')
        self.root.resizable(False, False)
        
        # Store last IP info (dict) for save/export
        self.last_ip_info = None
        
        # Setup UI
        self.setup_ui()
        
    def setup_ui(self):
        # Main title
        title_label = tk.Label(self.root, text="Network Information Tool", 
                              font=("Arial", 18, "bold"), fg="#00FF00", bg='black')
        title_label.pack(pady=12)
        
        # Main frame for buttons and results
        main_frame = tk.Frame(self.root, bg='black')
        main_frame.pack(pady=6, padx=12, fill="both", expand=True)
        
        # Public IP Section
        public_ip_frame = tk.Frame(main_frame, bg='black')
        public_ip_frame.pack(fill="x", pady=8)
        
        public_ip_btn = tk.Button(public_ip_frame, text="Get Public IP", 
                                 font=("Arial", 12, "bold"), fg="black", bg="#00FF00",
                                 command=self.get_public_ip_thread, width=18, height=1)
        public_ip_btn.pack(side="left", padx=10)
        
        self.public_ip_value = tk.Label(public_ip_frame, text="Click button to get", 
                                       font=("Arial", 12), fg="#00FF00", bg='black', width=45, anchor="w")
        self.public_ip_value.pack(side="left", padx=10)

        # IP Info Section (new)
        ipinfo_frame = tk.Frame(main_frame, bg='black')
        ipinfo_frame.pack(fill="x", pady=8)

        ipinfo_btn = tk.Button(ipinfo_frame, text="Get IP Info", 
                               font=("Arial", 12, "bold"), fg="black", bg="#00FF00",
                               command=self.get_ip_info_thread, width=18, height=1)
        ipinfo_btn.pack(side="left", padx=10)

        save_ipinfo_btn = tk.Button(ipinfo_frame, text="Save IP Info to File", 
                                    font=("Arial", 12, "bold"), fg="black", bg="#00FF00",
                                    command=self.save_ip_info_to_file, width=18, height=1)
        save_ipinfo_btn.pack(side="left", padx=6)

        self.ipinfo_value = tk.Label(ipinfo_frame, text="IP info not fetched", 
                                    font=("Arial", 12), fg="#00FF00", bg='black', width=30, anchor="w")
        self.ipinfo_value.pack(side="left", padx=10)
        
        # Local IP Section
        local_ip_frame = tk.Frame(main_frame, bg='black')
        local_ip_frame.pack(fill="x", pady=8)
        
        local_ip_btn = tk.Button(local_ip_frame, text="Get Local IP", 
                                font=("Arial", 12, "bold"), fg="black", bg="#00FF00",
                                command=self.get_local_ip, width=18, height=1)
        local_ip_btn.pack(side="left", padx=10)
        
        self.local_ip_value = tk.Label(local_ip_frame, text="Click button to get", 
                                      font=("Arial", 12), fg="#00FF00", bg='black', width=45, anchor="w")
        self.local_ip_value.pack(side="left", padx=10)
        
        # MAC Address Section
        mac_frame = tk.Frame(main_frame, bg='black')
        mac_frame.pack(fill="x", pady=8)
        
        mac_btn = tk.Button(mac_frame, text="Get MAC Address", 
                           font=("Arial", 12, "bold"), fg="black", bg="#00FF00",
                           command=self.get_mac_address, width=18, height=1)
        mac_btn.pack(side="left", padx=10)
        
        self.mac_value = tk.Label(mac_frame, text="Click button to get", 
                                 font=("Arial", 12), fg="#00FF00", bg='black', width=45, anchor="w")
        self.mac_value.pack(side="left", padx=10)
        
        # Connected WiFi Section
        wifi_frame = tk.Frame(main_frame, bg='black')
        wifi_frame.pack(fill="x", pady=8)
        
        wifi_btn = tk.Button(wifi_frame, text="Get Connected WiFi Password", 
                            font=("Arial", 12, "bold"), fg="black", bg="#00FF00",
                            command=self.get_connected_wifi_password, width=25, height=1)
        wifi_btn.pack(side="left", padx=10)
        
        self.wifi_value = tk.Label(wifi_frame, text="Click button to get", 
                                  font=("Arial", 12), fg="#00FF00", bg='black', width=35, anchor="w")
        self.wifi_value.pack(side="left", padx=10)
        
        # WiFi Name Display
        wifi_name_frame = tk.Frame(main_frame, bg='black')
        wifi_name_frame.pack(fill="x", pady=6)
        
        wifi_name_label = tk.Label(wifi_name_frame, text="Connected WiFi:", 
                                  font=("Arial", 12, "bold"), fg="#00FF00", bg='black')
        wifi_name_label.pack(side="left", padx=10)
        
        self.wifi_name_value = tk.Label(wifi_name_frame, text="Not checked", 
                                       font=("Arial", 12), fg="#00FF00", bg='black')
        self.wifi_name_value.pack(side="left", padx=10)
        
        # Large output Text area for detailed info
        output_frame = tk.Frame(self.root, bg='black')
        output_frame.pack(fill="both", expand=True, padx=12, pady=(6,4))
        self.output_text = tk.Text(output_frame, height=10, bg="#0b0b0b", fg="#00FF00", insertbackground="#00FF00")
        self.output_text.pack(fill="both", expand=True, side="left")
        self.output_text.insert("1.0", "Detailed output will appear here.\n")
        self.output_text.config(state=tk.DISABLED)
        output_scroll = tk.Scrollbar(output_frame, command=self.output_text.yview)
        output_scroll.pack(side="right", fill="y")
        self.output_text.config(yscrollcommand=output_scroll.set)
        
        # Refresh All Button
        refresh_btn = tk.Button(self.root, text="Refresh All Information", 
                               font=("Arial", 12, "bold"), fg="black", bg="#00FF00",
                               command=self.refresh_all, width=24, height=1)
        refresh_btn.pack(pady=(4,10))
        
        # System info
        system_label = tk.Label(self.root, text=f"Operating System: {platform.system()} {platform.release()}", 
                               font=("Arial", 10), fg="#00FF00", bg='black')
        system_label.pack(side="bottom", pady=6)
        
    # ---------- Networking helpers ----------
    def safe_update_label(self, label_widget, text):
        label_widget.config(text=text)
        self.root.update_idletasks()

    def append_output(self, text):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, text + "\n")
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)

    # ---------- Public IP (improved) ----------
    def get_public_ip_thread(self):
        threading.Thread(target=self.get_public_ip, daemon=True).start()

    def get_public_ip(self):
        # Try several public endpoints, then fallback to local methods
        self.safe_update_label(self.public_ip_value, "Loading...")
        self.append_output("Fetching public IP...")
        public_ip = None
        try:
            # Prefer ipify
            r = requests.get('https://api.ipify.org?format=text', timeout=6)
            if r.status_code == 200 and r.text.strip():
                public_ip = r.text.strip()
            else:
                raise Exception("ipify returned non-200 or empty")
        except Exception:
            try:
                # Try ident.me
                r = requests.get('https://ident.me', timeout=6)
                if r.status_code == 200 and r.text.strip():
                    public_ip = r.text.strip()
            except Exception:
                pass

        # As fallback, try ipinfo.io/json and extract ip field
        if public_ip is None:
            try:
                r = requests.get('https://ipinfo.io/json', timeout=6)
                if r.status_code == 200:
                    j = r.json()
                    if 'ip' in j and j['ip']:
                        public_ip = j['ip']
                    elif 'ip' not in j and 'ip' in j.keys():
                        public_ip = j.get('ip')
                    else:
                        # some ipinfo instances return 'ip' missing but have 'bogon' etc. try 'ip' in text
                        public_ip = j.get('ip') or j.get('ip_address') or None
            except Exception:
                pass

        if public_ip:
            self.safe_update_label(self.public_ip_value, public_ip)
            self.append_output(f"Public IP: {public_ip}")
        else:
            self.safe_update_label(self.public_ip_value, "Not available")
            self.append_output("Public IP: Not available")

    # ---------- IP Info (new) ----------
    def get_ip_info_thread(self):
        threading.Thread(target=self.get_ip_info, daemon=True).start()

    def get_ip_info(self):
        # Fetch IP info (geolocation, city, region, country, org, timezone) using ipinfo.io first,
        # fallback to ip-api.com for more fields if needed.
        self.append_output("Fetching IP information (ipinfo.io -> fallback ip-api.com)...")
        self.safe_update_label(self.ipinfo_value, "Loading...")
        try:
            # Try ipinfo.io
            try:
                r = requests.get("https://ipinfo.io/json", timeout=7)
                if r.status_code == 200:
                    info = r.json()
                    # ensure ip exists, otherwise try extracting ip from other fields
                    if 'ip' not in info or not info.get('ip'):
                        # try to get IP separately
                        ip = None
                        try:
                            ip = requests.get('https://api.ipify.org?format=text', timeout=5).text.strip()
                        except Exception:
                            ip = None
                        if ip:
                            info['ip'] = ip
                else:
                    info = None
            except Exception:
                info = None

            # fallback to ip-api.com/json if ipinfo failed
            if not info:
                try:
                    # If we have a public ip label, use it, otherwise call ip-api for caller
                    ip_label = self.public_ip_value.cget("text")
                    if ip_label and ip_label not in ("Click button to get", "Loading...", "Not available"):
                        target = ip_label
                    else:
                        target = ""  # blank -> ip-api uses caller IP
                    url = f"http://ip-api.com/json/{target}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query,timezone"
                    r = requests.get(url, timeout=7)
                    if r.status_code == 200:
                        info = r.json()
                        # Normalize keys to be similar to ipinfo for display
                        if info.get("status") == "success":
                            info = {
                                "ip": info.get("query"),
                                "country": info.get("country"),
                                "region": info.get("regionName"),
                                "city": info.get("city"),
                                "zip": info.get("zip"),
                                "loc": f"{info.get('lat')},{info.get('lon')}",
                                "org": info.get("org") or info.get("isp"),
                                "asn": info.get("as"),
                                "timezone": info.get("timezone")
                            }
                        else:
                            info = {"error": info.get("message", "ip-api failure")}
                    else:
                        info = {"error": f"ip-api HTTP {r.status_code}"}
                except Exception as e:
                    info = {"error": str(e)}
            
            # store and display
            self.last_ip_info = info
            # Build human-friendly text
            if info is None:
                display = "IP info: not available"
            elif isinstance(info, dict) and info.get("error"):
                display = f"IP info error: {info.get('error')}"
            else:
                ip = info.get("ip", "N/A")
                city = info.get("city", info.get("region", "N/A"))
                region = info.get("region", "N/A")
                country = info.get("country", "N/A")
                loc = info.get("loc", "N/A")
                org = info.get("org", info.get("asn", "N/A"))
                timezone = info.get("timezone", "N/A")
                display = (f"{ip} — {city}, {region}, {country} | loc: {loc} | org: {org} | tz: {timezone}")
            
            self.safe_update_label(self.ipinfo_value, display if len(display) < 80 else display[:77] + "...")
            self.append_output("=== IP Info ===")
            # pretty-print JSON into output area
            pretty = json.dumps(info, indent=2, ensure_ascii=False)
            self.append_output(pretty)
        except Exception as e:
            self.safe_update_label(self.ipinfo_value, "Not available")
            self.append_output(f"IP Info: Error: {str(e)}")
            self.last_ip_info = {"error": str(e)}
    
    def save_ip_info_to_file(self):
        # Save the last IP info (self.last_ip_info) to a file (JSON). If not present, ask to fetch.
        if not self.last_ip_info:
            # Ask user whether to fetch now
            answer = messagebox.askyesno("IP Info not fetched", "IP info has not been fetched yet. Do you want to fetch it now?")
            if not answer:
                return
            # Fetch then save (do synchronously on a thread and wait)
            self.get_ip_info()
        
        # At this point last_ip_info should be present
        if not self.last_ip_info:
            messagebox.showerror("No IP Info", "Failed to obtain IP info to save.")
            return
        
        # Ask filename
        filename = filedialog.asksaveasfilename(defaultextension=".json",
                                                filetypes=[("JSON file", "*.json"), ("Text file", "*.txt"), ("All files","*.*")],
                                                title="Save IP info to file")
        if not filename:
            return
        try:
            with open(filename, "w", encoding="utf-8") as fh:
                json.dump(self.last_ip_info, fh, indent=2, ensure_ascii=False)
            messagebox.showinfo("Saved", f"IP info saved to:\n{filename}")
            self.append_output(f"Saved IP info to: {filename}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))
            self.append_output(f"Failed to save IP info: {e}")

    # ---------- Local IP and MAC ----------
    def get_local_ip(self):
        try:
            self.local_ip_value.config(text="Loading...")
            self.root.update()
            
            # Better method to determine active local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            except Exception:
                local_ip = socket.gethostbyname(socket.gethostname())
            finally:
                s.close()
            self.local_ip_value.config(text=local_ip)
            self.append_output(f"Local IP: {local_ip}")
        except Exception as e:
            self.local_ip_value.config(text="Not available")
            self.append_output(f"Local IP: Error: {e}")
    
    def get_mac_address(self):
        try:
            self.mac_value.config(text="Loading...")
            self.root.update()
            
            mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
            self.mac_value.config(text=mac)
            self.append_output(f"MAC Address: {mac}")
        except Exception as e:
            self.mac_value.config(text="Not available")
            self.append_output(f"MAC: Error: {e}")
    
    # ---------- WiFi password helpers (unchanged from original) ----------
    def request_root_privileges(self):
        """Request root privileges using pkexec or gksu"""
        try:
            if platform.system() == "Linux":
                if os.geteuid() == 0:
                    return True  # Already root
                
                # Try to get root privileges (launch separate process)
                script_path = os.path.abspath(__file__)
                
                try:
                    subprocess.run(['pkexec', 'python3', script_path], check=False)
                    return True
                except:
                    pass
                
                try:
                    subprocess.run(['gksu', 'python3', script_path], check=False)
                    return True
                except:
                    pass
                
                try:
                    subprocess.run(['kdesu', 'python3', script_path], check=False)
                    return True
                except:
                    pass
                
                messagebox.showwarning("Root Required", 
                                     "Please run this application as root for WiFi password functionality.\n\n"
                                     "Run in terminal: sudo python3 main.py")
                return False
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to request root privileges: {str(e)}")
            return False
    
    def get_connected_wifi_info_windows(self):
        """Get currently connected WiFi name and password on Windows"""
        try:
            command = "netsh wlan show interfaces"
            interfaces_output = subprocess.check_output(command, shell=True, text=True)
            
            ssid_match = re.search(r"SSID\s*:\s*(.*)", interfaces_output)
            if not ssid_match:
                return None, "Not connected to WiFi"
            
            connected_ssid = ssid_match.group(1).strip()
            command = f'netsh wlan show profile name="{connected_ssid}" key=clear'
            profile_output = subprocess.check_output(command, shell=True, text=True)
            
            key_match = re.search(r"Key Content\s*:\s*(.*)", profile_output)
            if key_match:
                return connected_ssid, key_match.group(1).strip()
            else:
                return connected_ssid, "Password not available"
                
        except subprocess.CalledProcessError:
            return None, "Error getting WiFi info"
        except Exception as e:
            return None, f"Error: {str(e)}"
    
    def get_connected_wifi_info_linux(self):
        """Get currently connected WiFi name and password on Linux"""
        try:
            command = "iwgetid -r"
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0 or not result.stdout.strip():
                return None, "Not connected to WiFi"
            
            connected_ssid = result.stdout.strip()
            
            # Try multiple methods to get the password with root privileges
            methods = [
                f"sudo cat /etc/NetworkManager/system-connections/'{connected_ssid}'.nmconnection 2>/dev/null | grep psk=",
                f"sudo cat /etc/NetworkManager/system-connections/{connected_ssid}.nmconnection 2>/dev/null | grep psk=",
                f"sudo cat /etc/wpa_supplicant/wpa_supplicant.conf 2>/dev/null | grep -A10 -B10 '{connected_ssid}' | grep psk"
            ]
            
            password = None
            for method in methods:
                result = subprocess.run(method, shell=True, capture_output=True, text=True)
                if result.returncode == 0 and "psk=" in result.stdout:
                    password_line = result.stdout.split('\n')[0]
                    password = password_line.split("psk=")[1].strip().strip('"')
                    break
            
            if password:
                return connected_ssid, password
            else:
                return connected_ssid, "Password not found (root required)"
                
        except Exception as e:
            return None, f"Error: {str(e)}"
    
    def get_connected_wifi_password(self):
        try:
            self.wifi_value.config(text="Loading...")
            self.wifi_name_value.config(text="Loading...")
            self.root.update()
            
            system = platform.system()
            
            if system == "Linux" and os.geteuid() != 0:
                # Request root privileges for Linux
                self.wifi_value.config(text="Requesting root privileges...")
                self.root.update()
                
                if not self.request_root_privileges():
                    self.wifi_value.config(text="Root privileges required")
                    self.wifi_name_value.config(text="Permission denied")
                    return
            
            if system == "Windows":
                ssid, password = self.get_connected_wifi_info_windows()
            elif system == "Linux":
                ssid, password = self.get_connected_wifi_info_linux()
            else:
                ssid, password = None, "Unsupported OS"
            
            if ssid:
                self.wifi_name_value.config(text=ssid)
                self.wifi_value.config(text=password)
                self.append_output(f"WiFi: {ssid} -> {password}")
            else:
                self.wifi_name_value.config(text="Not connected")
                self.wifi_value.config(text=password)
                self.append_output(f"WiFi: {password}")
                
        except Exception as e:
            self.wifi_value.config(text=f"Error: {str(e)}")
            self.wifi_name_value.config(text="Error")
            self.append_output(f"WiFi error: {e}")
    
    def refresh_all(self):
        # Run all main retrievals in threads to avoid UI freeze
        threading.Thread(target=self.get_public_ip, daemon=True).start()
        threading.Thread(target=self.get_local_ip, daemon=True).start()
        threading.Thread(target=self.get_mac_address, daemon=True).start()
        threading.Thread(target=self.get_connected_wifi_password, daemon=True).start()

def is_root():
    """Check if running as root"""
    return platform.system() == "Linux" and os.geteuid() == 0

if __name__ == "__main__":
    # Minimal check for interactive root behavior (keeps original logic)
    if platform.system() == "Linux" and not is_root():
        root = tk.Tk()
        root.withdraw()  # Hide main window
        response = messagebox.askyesno(
            "Root Privileges Required", 
            "For full WiFi password functionality, root privileges are required.\n\n"
            "Would you like to continue anyway?\n\n"
            "For full features, run as: sudo python3 main.py"
        )
        if not response:
            sys.exit()
        root.destroy()
    
    root = tk.Tk()
    app = NetworkInfoApp(root)
    root.mainloop()
