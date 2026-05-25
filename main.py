import os
import sys
import json
import time
import ctypes
import winreg
import socket
import asyncio
import threading
import webbrowser
import psutil
import re
import customtkinter as ctk
from tkinter import Canvas

def _ensure_default_config():
    base_dir = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
    cfg_path = os.path.join(base_dir, 'config.json')
    if not os.path.exists(cfg_path):
        with open(cfg_path, 'w') as f:
            json.dump({
                "LISTEN_HOST": "0.0.0.0",
                "LISTEN_PORT": 40443,
                "CONNECT_IP": "104.19.229.21",
                "CONNECT_PORT": 443,
                "FAKE_SNI": "hcaptcha.com"
            }, f, indent=4)
_ensure_default_config()

from utils.network_tools import get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector

def get_exe_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))

config_path = os.path.join(get_exe_dir(), 'config.json')

with open(config_path, 'r') as f:
    config = json.load(f)

LISTEN_HOST = config["LISTEN_HOST"]
LISTEN_PORT = config["LISTEN_PORT"]
FAKE_SNI = config["FAKE_SNI"].encode()
CONNECT_IP = config["CONNECT_IP"]
CONNECT_PORT = config["CONNECT_PORT"]
INTERFACE_IPV4 = get_default_interface_ipv4(CONNECT_IP)
DATA_MODE = "tls"
BYPASS_METHOD = "wrong_seq"

PROXY_SERVER = "http=127.0.0.1:10808;https=127.0.0.1:10808;socks=127.0.0.1:10808"

fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}

def bypass_routing_loop():
    try:
        output = os.popen("route print 0.0.0.0").read()
        gateway = None
        for line in output.split('\n'):
            parts = line.strip().split()
            if len(parts) >= 4 and parts[0] == '0.0.0.0':
                gateway = parts[2]
                if gateway != 'On-link' and not gateway.startswith('127.'):
                    break
        if gateway:
            os.system(f"route add {CONNECT_IP} mask 255.255.255.255 {gateway} METRIC 1 >nul 2>&1")
            return gateway
    except Exception:
        pass
    return None

def cleanup_routing():
    try:
        os.system(f"route delete {CONNECT_IP} mask 255.255.255.255 >nul 2>&1")
    except Exception:
        pass

def enable_windows_proxy():
    try:
        internet_settings = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 0, winreg.KEY_ALL_ACCESS)
        winreg.SetValueEx(internet_settings, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(internet_settings, 'ProxyServer', 0, winreg.REG_SZ, PROXY_SERVER)
        winreg.SetValueEx(internet_settings, 'ProxyOverride', 0, winreg.REG_SZ, "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>")
        winreg.CloseKey(internet_settings)
        internet_set_option = ctypes.windll.wininet.InternetSetOptionW
        internet_set_option(0, 39, 0, 0)
        internet_set_option(0, 37, 0, 0)
    except Exception:
        pass

def disable_windows_proxy():
    try:
        internet_settings = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 0, winreg.KEY_ALL_ACCESS)
        winreg.SetValueEx(internet_settings, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(internet_settings)
        internet_set_option = ctypes.windll.wininet.InternetSetOptionW
        internet_set_option(0, 39, 0, 0)
        internet_set_option(0, 37, 0, 0)
    except Exception:
        pass

def proxy_monitor_thread():
    while True:
        try:
            internet_settings = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 0, winreg.KEY_READ)
            proxy_enable, _ = winreg.QueryValueEx(internet_settings, 'ProxyEnable')
            winreg.CloseKey(internet_settings)
            if proxy_enable == 0:
                enable_windows_proxy()
        except Exception:
            pass
        time.sleep(3)

def print_ui_banner(gateway):
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"\033[92m[+] Engine Status    : RUNNING SECURELY\033[0m")
    print(f"\033[94m[+] Local Listener   : {LISTEN_HOST}:{LISTEN_PORT}\033[0m")
    print(f"\033[94m[+] Target Endpoint  : {CONNECT_IP}:{CONNECT_PORT}\033[0m")
    print(f"\033[94m[+] Spoofed SNI      : {FAKE_SNI.decode()}\033[0m")
    print(f"\033[94m[+] Active Interface : {INTERFACE_IPV4}\033[0m")
    print(f"\033[94m[+] Bypass Method    : {BYPASS_METHOD.upper()}\033[0m")
    print(f"\033[92m[+] Windows Proxy    : FORCED ON {PROXY_SERVER}\033[0m")

async def relay_main_loop(sock_1: socket.socket, sock_2: socket.socket, peer_task: asyncio.Task):
    try:
        loop = asyncio.get_running_loop()
        while True:
            data = await loop.sock_recv(sock_1, 65535)
            if not data:
                break
            await loop.sock_sendall(sock_2, data)
    except Exception:
        pass
    finally:
        try:
            sock_1.close()
        except:
            pass
        try:
            sock_2.close()
        except:
            pass
        if peer_task and not peer_task.done():
            peer_task.cancel()

async def handle(incoming_sock: socket.socket, incoming_remote_addr):
    outgoing_sock = None
    fake_injective_conn = None
    try:
        loop = asyncio.get_running_loop()
        if DATA_MODE == "tls":
            fake_data = ClientHelloMaker.get_client_hello_with(os.urandom(32), os.urandom(32), FAKE_SNI, os.urandom(32))
        else:
            return

        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)
        outgoing_sock.bind((INTERFACE_IPV4, 0))
        outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        src_port = outgoing_sock.getsockname()[1]
        fake_injective_conn = FakeInjectiveConnection(outgoing_sock, INTERFACE_IPV4, CONNECT_IP, src_port, CONNECT_PORT, fake_data, BYPASS_METHOD, incoming_sock)
        fake_injective_connections[fake_injective_conn.id] = fake_injective_conn
        
        try:
            await loop.sock_connect(outgoing_sock, (CONNECT_IP, CONNECT_PORT))
        except Exception:
            return

        if BYPASS_METHOD == "wrong_seq":
            try:
                await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), 2)
                if fake_injective_conn.t2a_msg == "unexpected_close":
                    return
            except Exception:
                return

        fake_injective_conn.monitor = False
        
        oti_task = asyncio.create_task(relay_main_loop(outgoing_sock, incoming_sock, None))
        ito_task = asyncio.create_task(relay_main_loop(incoming_sock, outgoing_sock, oti_task))
        
        await asyncio.gather(oti_task, ito_task, return_exceptions=True)

    except Exception:
        pass
    finally:
        if fake_injective_conn and fake_injective_conn.id in fake_injective_connections:
            fake_injective_conn.monitor = False
            del fake_injective_connections[fake_injective_conn.id]
        if outgoing_sock:
            try:
                outgoing_sock.close()
            except:
                pass
        if incoming_sock:
            try:
                incoming_sock.close()
            except:
                pass

def clean_asyncio_errors(loop, context):
    exc = context.get('exception')
    msg = context.get('message', '')
    if isinstance(exc, OSError) and getattr(exc, 'winerror', None) == 6:
        return
    if "Cancelling an overlapped future failed" in msg:
        return
    if "fatal error on transport" in msg.lower():
        return

async def main():
    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    mother_sock.listen()
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(clean_asyncio_errors)
    
    try:
        while True:
            incoming_sock, addr = await loop.sock_accept(mother_sock)
            incoming_sock.setblocking(False)
            incoming_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
            incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
            incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            asyncio.create_task(handle(incoming_sock, addr))
    except asyncio.CancelledError:
        pass
    finally:
        mother_sock.close()

class IORedirector:
    def __init__(self, log_func):
        self.log_func = log_func
        self.ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        
    def write(self, text):
        clean_text = self.ansi_escape.sub('', text)
        if clean_text:
            self.log_func(clean_text)
            
    def flush(self):
        pass

class TrafficChart(ctk.CTkFrame):
    def __init__(self, master, title, **kwargs):
        super().__init__(master, fg_color="#1E1E1E", corner_radius=24, **kwargs)
        self.title_lbl = ctk.CTkLabel(self, text=title, font=("Arial", 11, "bold"))
        self.title_lbl.pack(pady=(5, 0))
        self.canvas = Canvas(self, bg="#1E1E1E", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True, padx=10, pady=5)

    def update_single_line(self, data, line_color, bg_color):
        self.canvas.delete("all")
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w < 10 or h < 10 or not data: return
        
        max_val = max(data) if max(data) > 0 else 1
        coords = []
        for i, val in enumerate(data):
            x = (i / max(1, len(data) - 1)) * w
            y = h - ((val / max_val) * h)
            coords.append((x, y))
            
        if len(coords) > 1:
            poly = [(coords[0][0], h)] + coords + [(coords[-1][0], h)]
            self.canvas.create_polygon(poly, fill=bg_color, outline="")
            self.canvas.create_line(coords, fill=line_color, width=2)

class AriMandoApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("AriMando SNI-Spoofing")
        self.geometry("480x620")
        self.resizable(False, False)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.configure(fg_color="#121212")

        self.is_connected = False
        self.main_loop = None
        self.vpn_thread = None

        self.total_dl = 0
        self.total_ul = 0
        self.max_dl_speed = 0
        self.max_ul_speed = 0
        
        self.dl_speed_history = [0]
        self.ul_speed_history = [0]

        self._build_ui()
        
        sys.stdout = IORedirector(self._append_log)
        
        self.traffic_thread = threading.Thread(target=self._traffic_monitor_loop, daemon=True)
        self.traffic_thread.start()

    def _build_ui(self):
        self.nav_frame = ctk.CTkFrame(self, fg_color="#2A2A2A", bg_color="#121212", corner_radius=26, height=45)
        self.nav_frame.pack(pady=(15, 5), padx=20, fill="x")

        self.btn_home = ctk.CTkButton(self.nav_frame, text="HOME", corner_radius=20, fg_color="transparent", bg_color="transparent", hover_color="#3A3A3A", command=lambda: self._show_frame("HOME"))
        self.btn_home.pack(side="left", expand=True, fill="both", padx=(5, 2), pady=5)

        self.btn_config = ctk.CTkButton(self.nav_frame, text="CONFIG", corner_radius=20, fg_color="transparent", bg_color="transparent", hover_color="#3A3A3A", command=lambda: self._show_frame("CONFIG"))
        self.btn_config.pack(side="left", expand=True, fill="both", padx=2, pady=5)

        self.btn_traffic = ctk.CTkButton(self.nav_frame, text="TRAFFIC", corner_radius=20, fg_color="transparent", bg_color="transparent", hover_color="#3A3A3A", command=lambda: self._show_frame("TRAFFIC"))
        self.btn_traffic.pack(side="left", expand=True, fill="both", padx=(2, 5), pady=5)

        self.frames = {}
        
        self.frames["HOME"] = ctk.CTkFrame(self, fg_color="transparent")
        
        lbl_emoji = ctk.CTkLabel(self.frames["HOME"], text="🌐", font=("Arial", 110))
        lbl_emoji.pack(pady=(5, 0))
        
        lbl_title = ctk.CTkLabel(self.frames["HOME"], text="AriMando", font=("Arial", 32, "bold"))
        lbl_title.pack(pady=0)
        
        self.lbl_status = ctk.CTkLabel(self.frames["HOME"], text="Status: Disconnected", font=("Arial", 15), text_color="gray")
        self.lbl_status.pack(pady=(0, 5))

        totals_frame = ctk.CTkFrame(self.frames["HOME"], fg_color="transparent")
        totals_frame.pack(fill="x", padx=35, pady=(5, 10))
        
        self.box_dl_total = ctk.CTkFrame(totals_frame, fg_color="#1E1E1E", corner_radius=24, height=80)
        self.box_dl_total.pack(side="left", expand=True, fill="x", padx=(0, 10))
        self.box_dl_total.pack_propagate(False)
        ctk.CTkLabel(self.box_dl_total, text="Total Download", font=("Arial", 11), text_color="#F1C40F").pack(pady=(10, 0))
        self.lbl_dl_total = ctk.CTkLabel(self.box_dl_total, text="0 B", font=("Arial", 15, "bold"))
        self.lbl_dl_total.pack()

        self.box_ul_total = ctk.CTkFrame(totals_frame, fg_color="#1E1E1E", corner_radius=24, height=80)
        self.box_ul_total.pack(side="right", expand=True, fill="x", padx=(10, 0))
        self.box_ul_total.pack_propagate(False)
        ctk.CTkLabel(self.box_ul_total, text="Total Upload", font=("Arial", 11), text_color="#3498DB").pack(pady=(10, 0))
        self.lbl_ul_total = ctk.CTkLabel(self.box_ul_total, text="0 B", font=("Arial", 15, "bold"))
        self.lbl_ul_total.pack()

        self.btn_connect = ctk.CTkButton(self.frames["HOME"], text="CONNECT", font=("Arial", 18, "bold"), height=50, corner_radius=24, fg_color="#17A554", hover_color="#107C3E", command=self._toggle_connection)
        self.btn_connect.pack(fill="x", padx=35, pady=(5, 5))

        self.txt_logs = ctk.CTkTextbox(self.frames["HOME"], height=165, corner_radius=24, fg_color="#161616", text_color="#2ECC71", font=("Consolas", 11))
        self.txt_logs.pack(fill="x", padx=35, pady=(10, 5))
        self.txt_logs.insert("end", "System Initialized...\nReady to connect.\n")
        self.txt_logs.configure(state="disabled")

        lbl_github = ctk.CTkLabel(self.frames["HOME"], text="GitHub", font=("Arial", 13, "bold"), text_color="#3498DB", cursor="hand2")
        lbl_github.pack(side="bottom", pady=(0, 10))
        lbl_github.bind("<Button-1>", lambda e: webbrowser.open("https://github.com/aripath/arimando"))

        self.frames["CONFIG"] = ctk.CTkFrame(self, fg_color="transparent")
        self.txt_config = ctk.CTkTextbox(self.frames["CONFIG"], corner_radius=24, fg_color="#1E1E1E", font=("Consolas", 13))
        self.txt_config.pack(fill="both", expand=True, padx=20, pady=(10, 10))
        
        btn_frame = ctk.CTkFrame(self.frames["CONFIG"], fg_color="transparent")
        btn_frame.pack(fill="x", padx=20, pady=(0, 20))
        btn_save = ctk.CTkButton(btn_frame, text="SAVE", corner_radius=24, height=45, fg_color="#17A554", hover_color="#107C3E", command=self._save_config)
        btn_save.pack(side="left", expand=True, fill="x", padx=(0, 10))
        btn_reset = ctk.CTkButton(btn_frame, text="RESET", corner_radius=24, height=45, fg_color="#E67E22", hover_color="#D35400", command=self._load_config)
        btn_reset.pack(side="right", expand=True, fill="x", padx=(10, 0))

        self.frames["TRAFFIC"] = ctk.CTkFrame(self, fg_color="transparent")
        
        self.chart_dl = TrafficChart(self.frames["TRAFFIC"], "Download Activity", height=110)
        self.chart_dl.pack(fill="x", padx=20, pady=(10, 5))
        self.chart_dl.pack_propagate(False)
        
        self.chart_ul = TrafficChart(self.frames["TRAFFIC"], "Upload Activity", height=110)
        self.chart_ul.pack(fill="x", padx=20, pady=5)
        self.chart_ul.pack_propagate(False)
        
        self.info_grid = ctk.CTkFrame(self.frames["TRAFFIC"], fg_color="transparent")
        self.info_grid.pack(fill="both", expand=True, padx=15, pady=5)
        
        self.info_grid.columnconfigure((0, 1), weight=1)
        self.info_grid.rowconfigure((0, 1), weight=1)

        self._create_info_box(self.info_grid, 0, 0, "Current DL", "lbl_info_dl_speed", "#F1C40F")
        self._create_info_box(self.info_grid, 0, 1, "Current UL", "lbl_info_ul_speed", "#3498DB")
        self._create_info_box(self.info_grid, 1, 0, "Max DL Speed", "lbl_info_max_dl", "#2ECC71")
        self._create_info_box(self.info_grid, 1, 1, "Max UL Speed", "lbl_info_max_ul", "#9B59B6")

        self._show_frame("HOME")
        self._load_config()

    def _create_info_box(self, parent, row, col, title, attr_name, color):
        box = ctk.CTkFrame(parent, fg_color="#1E1E1E", corner_radius=24)
        box.grid(row=row, column=col, padx=5, pady=5, sticky="nsew")
        ctk.CTkLabel(box, text=title, font=("Arial", 14, "bold"), text_color=color).pack(side="top", pady=(10, 0))
        lbl = ctk.CTkLabel(box, text="0 B/s", font=("Arial", 22, "bold"))
        lbl.place(relx=0.5, rely=0.5, anchor="center")
        setattr(self, attr_name, lbl)

    def _append_log(self, text):
        self.after(0, self._append_log_safe, text)

    def _append_log_safe(self, text):
        self.txt_logs.configure(state="normal")
        self.txt_logs.insert("end", text)
        self.txt_logs.see("end")
        self.txt_logs.configure(state="disabled")

    def _show_frame(self, name):
        self.btn_home.configure(fg_color="#3A3A3A" if name == "HOME" else "transparent")
        self.btn_config.configure(fg_color="#3A3A3A" if name == "CONFIG" else "transparent")
        self.btn_traffic.configure(fg_color="#3A3A3A" if name == "TRAFFIC" else "transparent")

        for frame in self.frames.values():
            frame.pack_forget()
        self.frames[name].pack(fill="both", expand=True)

    def _load_config(self):
        try:
            with open(config_path, 'r') as f:
                data = f.read()
            self.txt_config.delete("1.0", "end")
            self.txt_config.insert("1.0", data)
        except Exception as e:
            self.txt_config.insert("1.0", '{"error": "Config not found"}')

    def _save_config(self):
        try:
            data = json.loads(self.txt_config.get("1.0", "end"))
            with open(config_path, 'w') as f:
                json.dump(data, f, indent=4)
            self._append_log("[+] Config saved successfully.\n")
        except Exception:
            self._append_log("[-] Failed to save config.\n")

    def _format_size(self, bytes_size):
        if bytes_size < 1024:
            return f"{bytes_size} B"
        elif bytes_size < 1024 * 1024:
            return f"{bytes_size/1024:.1f} KB"
        elif bytes_size < 1024 * 1024 * 1024:
            return f"{bytes_size/(1024*1024):.2f} MB"
        else:
            return f"{bytes_size/(1024*1024*1024):.2f} GB"

    def _traffic_monitor_loop(self):
        prev_io = psutil.net_io_counters()
        while True:
            time.sleep(1)
            curr_io = psutil.net_io_counters()
            dl_speed = curr_io.bytes_recv - prev_io.bytes_recv
            ul_speed = curr_io.bytes_sent - prev_io.bytes_sent
            prev_io = curr_io
            
            if self.is_connected:
                self.total_dl += dl_speed
                self.total_ul += ul_speed
                
                if dl_speed > self.max_dl_speed: self.max_dl_speed = dl_speed
                if ul_speed > self.max_ul_speed: self.max_ul_speed = ul_speed

                self.dl_speed_history.append(dl_speed)
                self.ul_speed_history.append(ul_speed)

                self.after(0, self._update_ui_traffic, dl_speed, ul_speed)
            else:
                self.after(0, self._update_ui_traffic, 0, 0)

    def _update_ui_traffic(self, dl_speed, ul_speed):
        self.lbl_dl_total.configure(text=self._format_size(self.total_dl))
        self.lbl_ul_total.configure(text=self._format_size(self.total_ul))
        
        self.lbl_info_dl_speed.configure(text=f"{self._format_size(dl_speed)}/s")
        self.lbl_info_ul_speed.configure(text=f"{self._format_size(ul_speed)}/s")
        self.lbl_info_max_dl.configure(text=f"{self._format_size(self.max_dl_speed)}/s")
        self.lbl_info_max_ul.configure(text=f"{self._format_size(self.max_ul_speed)}/s")

        if self.is_connected:
            self.chart_dl.update_single_line(self.dl_speed_history, "#2ECC71", "#104A29")
            self.chart_ul.update_single_line(self.ul_speed_history, "#3498DB", "#123550")

    def _toggle_connection(self):
        if self.is_connected:
            self.is_connected = False
            self.lbl_status.configure(text="Status: Disconnected", text_color="gray")
            self.btn_connect.configure(text="CONNECT", fg_color="#17A554", hover_color="#107C3E")
            self._append_log("\n[-] Initiating Disconnect...\n")
            self._stop_core()
        else:
            self.is_connected = True
            self.lbl_status.configure(text="RUNNING SECURELY", text_color="#2ECC71")
            self.btn_connect.configure(text="DISCONNECT", fg_color="#E74C3C", hover_color="#C0392B")
            self._append_log("\n[+] Starting Secure Tunnel...\n")
            self.vpn_thread = threading.Thread(target=self._start_core, daemon=True)
            self.vpn_thread.start()

    def _start_core(self):
        global INTERFACE_IPV4, gateway, fake_tcp_injector
        if not INTERFACE_IPV4:
            self._append_log("[!] Error: No active IPv4 interface.\n")
            return

        w_filter = f"tcp and ((ip.SrcAddr == {INTERFACE_IPV4} and ip.DstAddr == {CONNECT_IP}) or (ip.SrcAddr == {CONNECT_IP} and ip.DstAddr == {INTERFACE_IPV4}))"
        fake_tcp_injector = FakeTcpInjector(w_filter, fake_injective_connections)
        threading.Thread(target=fake_tcp_injector.run, daemon=True).start()
        
        gateway = bypass_routing_loop()
        enable_windows_proxy()
        threading.Thread(target=proxy_monitor_thread, daemon=True).start()
        
        print_ui_banner(gateway)
        
        self.main_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.main_loop)
        try:
            self.main_loop.run_until_complete(main())
        except Exception as e:
            pass

    def _stop_core(self):
        if self.main_loop and self.main_loop.is_running():
            self.main_loop.call_soon_threadsafe(self.main_loop.stop)
        disable_windows_proxy()
        cleanup_routing()
        self._append_log("[+] System Proxy and Routing Rules restored.\n")

if __name__ == "__main__":
    app = AriMandoApp()
    app.mainloop()