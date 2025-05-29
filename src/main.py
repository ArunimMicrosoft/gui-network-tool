import matplotlib
matplotlib.use('Agg')

import tkinter as tk
import threading
import subprocess
import platform
import requests
import socket
import os
import sys
import random
import time
import tempfile
import webbrowser
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas as pdf_canvas
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Image, Preformatted
from reportlab.lib.enums import TA_CENTER

class ToolTip:
    """Tooltip for Tkinter widgets."""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tipwindow = None
        widget.bind("<Enter>", self.show_tip)
        widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, event=None):
        if self.tipwindow or not self.text:
            return
        x, y, _, cy = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += cy + self.widget.winfo_rooty() + 25
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            tw, text=self.text, justify=tk.LEFT,
            background="#ffffe0", relief=tk.SOLID, borderwidth=1,
            font=("tahoma", "10", "normal")
        )
        label.pack(ipadx=1)

    def hide_tip(self, event=None):
        if self.tipwindow:
            self.tipwindow.destroy()
        self.tipwindow = None

class NetworkToolApp:
    """Main application class for the Network Utility tool."""

    def __init__(self, master):
        self.master = master
        self.master.title("Network Utility by Arunim Pandey")
        self.master.geometry("1000x700")
        self._setup_icon()
        self._setup_layout()
        self._setup_buttons()
        self._setup_tooltips()
        self.pings = []
        self.max_points = 60

    def _setup_icon(self):
        """Set application window icon based on OS."""
        icon_path_ico = os.path.join(os.path.dirname(__file__), 'icon.ico')
        icon_path_png = os.path.join(os.path.dirname(__file__), 'icon.png')
        try:
            if sys.platform.startswith('win'):
                self.master.iconbitmap(icon_path_ico)
            elif os.path.exists(icon_path_png):
                img = tk.PhotoImage(file=icon_path_png)
                self.master.iconphoto(True, img)
        except Exception:
            pass

    def _setup_layout(self):
        """Initialize and pack all main frames and widgets."""
        self.header = tk.Label(
            self.master, text="Network Utility",
            font=("Comic Sans MS", 22, "bold"),
            fg="#4B0082", bg="#E0E7FF", pady=10,
            justify="center", anchor="center"
        )
        self.header.pack(side=tk.TOP, fill=tk.X, pady=(0, 10))

        self.content_frame = tk.Frame(self.master)
        self.content_frame.pack(fill=tk.BOTH, expand=True)

        self.left_frame = tk.Frame(self.content_frame, bg="#e6eaf0", bd=2, relief=tk.GROOVE, width=260)
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(10, 0), pady=10)
        self.left_frame.pack_propagate(False)

        self.right_frame = tk.Frame(self.content_frame)
        self.right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=0, pady=10)

        self.search_frame = tk.Frame(self.right_frame, bg="#F0F8FF")
        self.search_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 10), anchor="center")
        self.entry = tk.Entry(
            self.search_frame, font=("Comic Sans MS", 16),
            bg="#FFF8DC", fg="#888888", relief=tk.GROOVE, bd=3,
            width=40, justify="center"
        )
        self.entry.pack(padx=10, pady=5, fill=tk.X, expand=True)
        self.entry.insert(0, "Enter IP/domain to diagnose")
        self.entry_is_watermark = True
        self.entry.bind("<FocusIn>", self._on_entry_focus_in)
        self.entry.bind("<FocusOut>", self._on_entry_focus_out)

        self.graph_text = tk.Text(
            self.right_frame, bg="#ffffff", fg="#000000",
            font=("Consolas", 11), wrap=tk.NONE
        )
        self.graph_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        self.graph_text.config(state=tk.DISABLED)

        self.graph_canvas = tk.Canvas(
            self.right_frame, bg="#ffffff", height=300
        )
        self.graph_canvas.bind("<Configure>", self.on_canvas_resize)

        self.footer = tk.Label(
            self.master,
            text="Network Utility | ©Built by Arunim Pandey| Suggestions:arunimpandey2903@hotmail.com | Version: 1.4.2(Revised) Release 30 June 2025",
            font=("Comic Sans MS", 11, "bold italic"),
            fg="#fff", bg="#4B0082", pady=8, bd=2, relief=tk.RIDGE
        )
        self.footer.pack(side=tk.BOTTOM, fill=tk.X)

    def _on_entry_focus_in(self, event):
        if self.entry_is_watermark:
            self.entry.delete(0, tk.END)
            self.entry.config(fg="#333333")
            self.entry_is_watermark = False

    def _on_entry_focus_out(self, event):
        if not self.entry.get():
            self.entry.insert(0, "Enter IP/domain to diagnose")
            self.entry.config(fg="#888888")
            self.entry_is_watermark = True

    def _setup_buttons(self):
        """Create and grid all main function buttons."""
        btn_style = {
            "font": ("Consolas", 13, "bold"),
            "bg": "#23272e", "fg": "#ffffff",
            "activebackground": "#3a4050", "activeforeground": "#ffffff",
            "relief": tk.RAISED, "bd": 2, "width": 32, "cursor": "hand2",
            "anchor": "center", "justify": "center", "padx": 14, "pady": 8, "wraplength": 320
        }
        stop_btn_style = btn_style.copy()
        stop_btn_style.update({"bg": "#b22222", "fg": "#fff", "activebackground": "#e57373"})
        reset_btn_style = btn_style.copy()
        reset_btn_style.update({"bg": "#228b22", "fg": "#fff", "activebackground": "#7be67b"})
        help_btn_style = btn_style.copy()
        help_btn_style.update({"bg": "#007acc", "fg": "#fff", "activebackground": "#005a9e"})

        self.send_button = tk.Button(self.left_frame, text="Send Ping", command=self.send_ping, **btn_style)
        self.route_button = tk.Button(self.left_frame, text="Show Route Table", command=self.show_route_table, **btn_style)
        self.geoasn_button = tk.Button(self.left_frame, text="Geo & ASN Lookup", command=self.show_geoasn, **btn_style)
        self.nexthop_button = tk.Button(self.left_frame, text="Show Next Hops", command=self.show_next_hops, **btn_style)
        self.pcap_button = tk.Button(self.left_frame, text="Advanced Packet Capture", command=self.advanced_packet_capture, **btn_style)
        self.portscan_button = tk.Button(self.left_frame, text="Port Scan Capture", command=self.port_scan_capture, **btn_style)
        self.speedtest_button = tk.Button(self.left_frame, text="Bandwidth Speed Test", command=self.bandwidth_speed_test, **btn_style)
        self.pinggraph_toggle_button = tk.Button(self.left_frame, text="Start Ping Graph", command=self.toggle_ping_graph, **btn_style)
        self.subnet_button = tk.Button(self.left_frame, text="Divide Subnet", command=self.divide_subnet, **btn_style)
        self.stopall_button = tk.Button(self.left_frame, text="🛑 Stop All Functions", command=self.stop_all, **stop_btn_style)
        self.reset_button = tk.Button(self.left_frame, text="🔄 Reset Output & Input", command=self.reset_canvas, **reset_btn_style)
        self.health_report_button = tk.Button(
            self.left_frame, text="Auto Network Health Report (PDF)",
            command=self.generate_network_health_report,
            bg="#005a9e", fg="#fff", activebackground="#007acc",
            font=("Consolas", 13, "bold"), width=32, relief=tk.RAISED, bd=2,
            cursor="hand2", anchor="center", justify="center", padx=14, pady=8, wraplength=320
        )
        self.help_button = tk.Button(
            self.left_frame, text="Technical Help & Documentation",
            command=self.show_technical_documentation, **help_btn_style
        )

        buttons = [
            self.send_button, self.route_button, self.geoasn_button, self.nexthop_button,
            self.pcap_button, self.portscan_button, self.speedtest_button,
            self.subnet_button, self.pinggraph_toggle_button,
            self.stopall_button, self.reset_button, self.health_report_button,
            self.help_button
        ]
        for i, btn in enumerate(buttons):
            btn.grid(row=i, column=0, sticky="ew", padx=8, pady=4)
        self.left_frame.grid_rowconfigure(len(buttons), weight=1)

    def _setup_tooltips(self):
        """Attach tooltips to main buttons."""
        ToolTip(self.send_button, "Ping the entered host or IP! 🏓")
        ToolTip(self.portscan_button, "Scan for open ports on the target! 🔍")
        ToolTip(self.pinggraph_toggle_button, "Start a real-time ping graph! 📈")
        ToolTip(self.speedtest_button, "Test your bandwidth speed! 🚀")
        ToolTip(self.reset_button, "Clear the canvas and search bar! 🧹")
        ToolTip(self.stopall_button, "Stop all running operations! 🛑")
        ToolTip(self.subnet_button, "Divide a network into smaller subnets! 🧩")

    def on_canvas_resize(self, event):
        if getattr(self, "pinggraph_running", False) and self.pings:
            self.draw_ping_graph()

    def update_graph_text(self, text, tags=None):
        self.show_text()
        self.clear_watermark()
        self.graph_text.config(state=tk.NORMAL)
        self.graph_text.delete("1.0", tk.END)
        self.graph_text.tag_configure("header", font=("Consolas", 14, "bold"), foreground="#005a9e")
        self.graph_text.tag_configure("important", font=("Consolas", 12, "bold"), foreground="#b22222")
        self.graph_text.tag_configure("success", font=("Consolas", 12, "bold"), foreground="#228b22")
        self.graph_text.tag_configure("info", font=("Consolas", 11, "bold"), foreground="#007acc")
        self.graph_text.tag_configure("default", font=("Consolas", 11), foreground="#23272e")
        self.graph_text.tag_configure("witty", font=("Comic Sans MS", 11, "italic"), foreground="#ff8800")
        self.graph_text.tag_configure("footer", font=("Consolas", 10, "italic"), foreground="#4B0082")
        lines = text.splitlines()
        for line in lines:
            tag = "default"
            if "error" in line.lower() or "fail" in line.lower():
                tag = "important"
            elif "success" in line.lower() or "open" in line.lower() or "complete" in line.lower():
                tag = "success"
            elif "ping statistics" in line.lower() or "scan" in line.lower() or "report" in line.lower():
                tag = "header"
            elif "stop" in line.lower() or "stopped" in line.lower():
                tag = "important"
            elif "waiting" in line.lower() or "please wait" in line.lower():
                tag = "info"
            elif "wizard" in line.lower() or "gnomes" in line.lower() or "🍕" in line or "🧙" in line or "🦄" in line:
                tag = "witty"
            elif "network utility" in line.lower():
                tag = "footer"
            self.graph_text.insert(tk.END, line + "\n", tag)
        self.graph_text.config(state=tk.DISABLED)

    def draw_ping_graph(self):
        self.show_canvas()
        width = self.graph_canvas.winfo_width()
        height = self.graph_canvas.winfo_height()
        margin = 40
        max_points = self.max_points
        pings = self.pings[-max_points:]

        self.graph_canvas.delete("all")
        self.graph_canvas.create_line(margin, height - margin, width - margin, height - margin, fill="#888", width=2)
        self.graph_canvas.create_line(margin, margin, margin, height - margin, fill="#888", width=2)

        valid_pings = [p for p in pings if p is not None]
        if valid_pings:
            min_ping = min(valid_pings)
            max_ping = max(valid_pings)
            if min_ping == max_ping:
                min_ping = max_ping - 1
            span = max(max_ping - min_ping, 1)
            plot_width = width - 2 * margin
            plot_height = height - 2 * margin

            n = len(pings)
            if n > 1:
                x_spacing = plot_width / (max_points - 1)
                x_offset = margin + ((max_points - n) * x_spacing) / 2
            else:
                x_spacing = plot_width
                x_offset = margin + plot_width / 2

            prev_x, prev_y = None, None
            for i, val in enumerate(pings):
                if val is not None:
                    x = x_offset + i * x_spacing
                    y = height - margin - int((val - min_ping) / span * plot_height)
                    color = "#39C800" if val < 60 else "#FFD700" if val < 150 else "#FF5555"
                    self.graph_canvas.create_oval(x-4, y-4, x+4, y+4, fill=color, outline=color)
                    if prev_x is not None and prev_y is not None:
                        self.graph_canvas.create_line(prev_x, prev_y, x, y, fill=color, width=3)
                    prev_x, prev_y = x, y

            self.graph_canvas.create_text(margin//2, margin, text=f"{max_ping:.1f} ms", anchor="w", fill="#b22222", font=("Consolas", 12, "bold"))
            self.graph_canvas.create_text(margin//2, height-margin, text=f"{min_ping:.1f} ms", anchor="w", fill="#228b22", font=("Consolas", 12, "bold"))
        else:
            self.graph_canvas.create_text(width//2, height//2, text="Waiting for ping data...", fill="#888", font=("Consolas", 16, "bold italic"))

        self.graph_canvas.create_text(width//2, 28, text="🖧 PING LATENCY GRAPH 🖧", fill="#005a9e", font=("Consolas", 18, "bold"))
        if pings:
            last_ping = pings[-1] if pings[-1] is not None else 'timeout'
        else:
            last_ping = 'N/A'
        color = "#228b22" if isinstance(last_ping, (int, float)) and last_ping < 60 else "#FFD700" if isinstance(last_ping, (int, float)) and last_ping < 150 else "#FF5555"
        self.graph_canvas.create_text(width//2, height-18, text=f"Last: {last_ping} ms", fill=color, font=("Consolas", 14, "bold"))

    def send_ping(self):
        host = self.entry.get().strip()
        if not host or host.lower() == "enter ip/domain to diagnose":
            self.show_text()
            self.update_graph_text("Please enter a host or IP in the search bar.")
            return
        import platform
        import subprocess
        import time

        self.stop_all_flag = False  # Reset stop flag when starting
        self._last_ping_stats = ""  # Store last ping statistics
        self.show_text()
        self.update_graph_text(
            "Pinging...\nTo Stop kindly click on Stop all function button\n"
        )

        def ping_task():
            lines = []
            stats_lines = []
            # Use system ping with -t (Windows) or continuous (Linux/Mac)
            if platform.system().lower() == "windows":
                cmd = ["ping", "-t", host]
            else:
                cmd = ["ping", host]
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                while not self.stop_all_flag:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    lines.append(line)
                    # Only keep last 20 lines for display
                    if len(lines) > 20:
                        lines.pop(0)
                    self.update_graph_text(
                        "Pinging...\nTo Stop kindly click on Stop all function button\n" +
                        "".join(lines)
                    )
                    # Collect lines for statistics (last 10 lines)
                    stats_lines.append(line)
                    if len(stats_lines) > 10:
                        stats_lines.pop(0)
                # After stopping, read remaining lines for stats
                try:
                    while True:
                        line = proc.stdout.readline()
                        if not line:
                            break
                        stats_lines.append(line)
                        if len(stats_lines) > 20:
                            stats_lines.pop(0)
                except Exception:
                    pass
                proc.terminate()
                # Extract statistics from the last lines
                stats_text = "".join(stats_lines)
                # Windows: look for "Ping statistics for"
                # Linux/Mac: look for "statistics"
                stats = []
                for l in stats_lines:
                    if ("statistics" in l.lower()) or ("packets" in l.lower()) or ("minimum" in l.lower()) or ("avg" in l.lower()) or ("maximum" in l.lower()) or ("loss" in l.lower()):
                        stats.append(l)
                if not stats:
                    # fallback: show last 5 lines
                    stats = stats_lines[-5:]
                self._last_ping_stats = "Ping Statistics:\n" + "".join(stats)
            except Exception as e:
                self._last_ping_stats = f"Ping failed: {e}"
                self.update_graph_text(f"Ping failed: {e}")

        threading.Thread(target=ping_task, daemon=True).start()

    def show_geoasn(self):
        host = self.entry.get().strip()
        if not host or host.lower() == "enter ip/domain to diagnose":
            self.update_graph_text("Please enter a host or IP in the search bar.")
            return
        self.update_graph_text("This process could take a few seconds...\nFetching Geo & ASN info...")

        def geoasn_task():
            try:
                try:
                    ip = socket.gethostbyname(host)
                except Exception:
                    ip = host
                response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    output = (
                        f"IP: {data.get('ip', 'N/A')}\n"
                        f"Hostname: {data.get('hostname', 'N/A')}\n"
                        f"City: {data.get('city', 'N/A')}\n"
                        f"Region: {data.get('region', 'N/A')}\n"
                        f"Country: {data.get('country', 'N/A')}\n"
                        f"Location: {data.get('loc', 'N/A')}\n"
                        f"Org/ASN: {data.get('org', 'N/A')}\n"
                        f"Timezone: {data.get('timezone', 'N/A')}\n"
                    )
                elif response.status_code == 404:
                    output = "No Geo & ASN info found for this IP/host. Please enter a valid public IP or hostname."
                else:
                    output = f"Failed to fetch info: {response.status_code}"
            except Exception as e:
                output = f"Failed to fetch Geo & ASN info:\n{e}"
            self.update_graph_text(output)
        threading.Thread(target=geoasn_task, daemon=True).start()

    def show_next_hops(self):
        import platform
        import subprocess
        import socket
        import threading

        host = self.entry.get().strip()
        if not host or host.lower() == "enter ip/domain to diagnose":
            self.show_text()
            self.update_graph_text("Please enter a host or IP in the search bar.")
            return
        self.show_text()
        self.update_graph_text("Tracing route (up to 5 hops)...\nThis may take a few seconds...")

        def nexthop_task():
            try:
                try:
                    ip = socket.gethostbyname(host)
                except Exception:
                    ip = host

                if platform.system().lower() == "windows":
                    command = [
                        "powershell",
                        "-Command",
                        f"Test-NetConnection -ComputerName {ip} -TraceRoute"
                    ]
                    output = subprocess.check_output(command, universal_newlines=True, stderr=subprocess.STDOUT)
                    # Parse TraceRoute section
                    hops = []
                    in_trace = False
                    for line in output.splitlines():
                        if "TraceRoute" in line:
                            in_trace = True
                            continue
                        if in_trace:
                            if line.strip() == "":
                                break
                            hops.append(line.strip())
                    hops = [h for h in hops if h]  # Remove empty lines

                    # Format hops for clarity
                    formatted = []
                    for idx, hop in enumerate(hops[:5], 1):
                        if hop == "0.0.0.0":
                            formatted.append(f"Hop {idx}: Request timed out")
                        else:
                            formatted.append(f"Hop {idx}: {hop}")

                    # Add destination if present and not already in hops
                    if len(hops) > 5 and hops[-1] != "0.0.0.0":
                        formatted.append(f"Destination: {hops[-1]}")

                    hops_output = "\n".join(formatted)
                    self.update_graph_text(
                        f"PowerShell TraceRoute to {host} (up to 5 hops):\n\n{hops_output}\n\n"
                        "Note: 'Request timed out' means the hop did not reply (timeout)."
                    )
                else:
                    # Fallback to traceroute on Linux/Mac
                    command = ["traceroute", "-m", "5", ip]
                    output = subprocess.check_output(command, universal_newlines=True, stderr=subprocess.STDOUT)
                    # Parse and format output for clarity
                    lines = output.splitlines()
                    formatted = []
                    for line in lines[1:6]:  # Skip the header, show up to 5 hops
                        if "*" in line:
                            formatted.append(f"{line.split()[0]}: Request timed out")
                        else:
                            formatted.append(line)
                    hops_output = "\n".join(formatted)
                    self.update_graph_text(
                        f"Traceroute to {host} (up to 5 hops):\n\n{hops_output}\n\n"
                        "Note: 'Request timed out' means the hop did not reply."
                    )
            except Exception as e:
                self.update_graph_text(f"Failed to get next hops:\n{e}")

        threading.Thread(target=nexthop_task, daemon=True).start()

    def advanced_packet_capture(self):
        host = self.entry.get().strip()
        if not host or host.lower() == "enter ip/domain to diagnose":
            self.update_graph_text("Please enter a host or IP in the search bar.")
            return
        self.update_graph_text(
            f"[Advanced Packet Capture]\n\nCollecting active connections for {host}...\n(This may take a few seconds)"
        )

        def pcap_task():
            import platform
            import subprocess
            import socket

            try:
                ip = host
                try:
                    ip = socket.gethostbyname(host)
                except Exception:
                    pass
                if platform.system().lower() == "windows":
                    command = ["netstat", "-ano"]
                else:
                    command = ["netstat", "-tunap"]

                proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                output_lines = []
                while True:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    output_lines.append(line)
                    # Only show lines related to the target IP/domain or protocol headers
                    filtered = [l for l in output_lines if ip in l or l.lower().startswith("proto") or l.lower().startswith("tcp") or l.lower().startswith("udp")]
                    if filtered and len(filtered) > 3:
                        display = f"[Advanced Packet Capture]\n\nActive Connections for {host}\n\n" + "".join(filtered)
                    else:
                        display = f"[Advanced Packet Capture]\n\nNo active connections found for {host}.\n\nFull netstat output:\n\n" + "".join(output_lines)
                    self.update_graph_text(display)
            except Exception as e:
                self.update_graph_text(f"Packet capture failed:\n{e}")

        threading.Thread(target=pcap_task, daemon=True).start()

    def port_scan_capture(self):
        host = self.entry.get().strip()
        if not host:
            self.update_graph_text("Please enter a host or IP.")
            return

        witty_messages = [
            "Scanning the digital seas... 🏴‍☠️",
            "Knocking on every door... 🚪",
            "Looking for open windows (and ports)... 🪟",
            "Port by port, byte by byte... 🧮",
            "Is anyone home on this port? 🏠",
            "TCP detective at work... 🕵️‍♂️",
            "Counting open and closed gates... 🚧",
            "Almost there, hang tight! 🦥",
            "Still scanning, don't go for coffee yet! ☕",
            "Patience is a port-scanner's virtue... 🧘",
            "Ports are like chocolates, you never know what you'll get! 🍫",
            "Hoping for open ports, not open cans of worms! 🪱",
            "This scan is more thorough than your last spring cleaning! 🧹"
        ]
        animation = ["[=     ]", "[==    ]", "[===   ]", "[ ===  ]", "[  === ]", "[   ===]", "[    ==]", "[     =]", "[      ]"]
        self.stop_all_flag = False  # Reset stop flag

        self.update_graph_text(
            "[Port Scan Capture]\n\nScanning ALL ports (1-65535)...\n(This may take several minutes)\n"
        )

        def scan_task():
            import socket
            import time
            import random

            try:
                ip = socket.gethostbyname(host)
            except Exception:
                ip = host

            open_ports = []
            closed_ports = 0
            total_ports = 65535
            start_time = time.time()
            anim_idx = 0
            last_lines = []

            for port in range(1, total_ports + 1):
                if self.stop_all_flag:
                    witty = random.choice(witty_messages)
                    self.update_graph_text(
                        f"[Port Scan Capture]\n\nScan stopped by user at port {port}.\n{witty}\n"
                    )
                    return
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.2)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                        line = f"Port {port}: OPEN 🎉"
                    else:
                        closed_ports += 1
                        line = f"Port {port}: closed"
                    sock.close()
                except Exception as e:
                    closed_ports += 1
                    line = f"Port {port}: error ({e})"

                last_lines.append(line)
                # Keep only the last 30 lines for real-time display
                if len(last_lines) > 30:
                    last_lines.pop(0)

                # Show witty message and animation every 20 ports or on last port
                if port % 20 == 0 or port == total_ports:
                    elapsed = time.time() - start_time
                    witty = random.choice(witty_messages)
                    anim = animation[anim_idx % len(animation)]
                    anim_idx += 1
                    progress = (
                        f"\n{witty} {anim}\n"
                        f"Scanned {port}/{total_ports} ports. Elapsed: {int(elapsed)}s\n"
                        f"Open: {len(open_ports)} | Closed: {closed_ports}\n"
                    )
                    display = (
                        f"[Port Scan Capture]\n\nScanning {ip} on all ports (1-65535):\n\n"
                        + "\n".join(last_lines)
                        + progress
                    )
                    self.update_graph_text(display)

            elapsed = time.time() - start_time
            witty = random.choice(witty_messages)
            summary = (
                f"\n🎉 Scan complete in {int(elapsed)} seconds! 🎉\n"
                f"Total open ports: {len(open_ports)}\n"
                f"Total closed: {closed_ports}\n"
                f"Open ports: {', '.join(str(p) for p in open_ports) if open_ports else 'None'}\n"
                f"{witty}\n"
                "Remember: With great power comes great responsibility! 🕷️"
            )
            # Show the full summary at the end
            self.update_graph_text(
                f"[Port Scan Capture]\n\nScanning {ip} on all ports (1-65535):\n\n"
                + "\n".join(last_lines)
                + summary
            )

        threading.Thread(target=scan_task, daemon=True).start()

    def start_ping_graph(self):
        import threading, time, random, re, platform, subprocess, socket

        host = self.entry.get().strip()
        if not host or host.lower() == "enter ip/domain to diagnose":
            self.update_graph_text("Please enter a host or IP.")
            return

        self.pinggraph_running = True
        self.stop_all_flag = False  # Ensure stop flag is reset
        self.pings = []
        self.show_canvas()
        self.graph_canvas.delete("all")

        def ping_task():
            count = 0
            while self.pinggraph_running and not self.stop_all_flag:
                count += 1
                try:
                    ip = socket.gethostbyname(host)
                    if platform.system().lower() == "windows":
                        cmd = ["ping", "-n", "1", ip]
                    else:
                        cmd = ["ping", "-c", "1", ip]
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                    output = proc.stdout
                    match = re.search(r'time[=<]?\s*([\d\.]+)\s*ms', output)
                    ms = float(match.group(1)) if match else None
                except Exception:
                    ms = None
                self.pings.append(ms)
                if len(self.pings) > self.max_points:
                    self.pings.pop(0)
                self.draw_ping_graph()
                time.sleep(0.5)

        threading.Thread(target=ping_task, daemon=True).start()

    def toggle_ping_graph(self):
        if not hasattr(self, "pinggraph_running") or not self.pinggraph_running:
            self.stop_all_flag = False  # Ensure stop flag is reset
            self.pinggraph_running = True
            self.pinggraph_toggle_button.config(text="Stop Ping Graph")
            self.start_ping_graph()
        else:
            self.pinggraph_running = False
            self.pinggraph_toggle_button.config(text="Start Ping Graph")
            # Show the last graph
            self.draw_ping_graph()  # Draw the last state of the graph

            # Prepare summary
            valid_pings = [p for p in self.pings if p is not None]
            if valid_pings:
                min_ping = min(valid_pings)
                max_ping = max(valid_pings)
                avg_ping = sum(valid_pings) / len(valid_pings)
                last_ping = valid_pings[-1]
                timeouts = len([p for p in self.pings if p is None])
                summary = (
                    "[Ping Graph Summary]\n\n"
                    f"Total samples: {len(self.pings)}\n"
                    f"Timeouts: {timeouts}\n"
                    f"Min ping: {min_ping:.2f} ms\n"
                    f"Max ping: {max_ping:.2f} ms\n"
                    f"Avg ping: {avg_ping:.2f} ms\n"
                    f"Last ping: {last_ping:.2f} ms\n"
                )
            else:
                summary = "[Ping Graph Summary]\n\nNo valid ping data collected."

            # Show both the graph and the summary: keep canvas visible, show summary in text below
            self.graph_text.config(state=tk.NORMAL)
            self.graph_text.delete("1.0", tk.END)
            self.graph_text.tag_configure(
                "centered",
                font=("Comic Sans MS", 14, "bold"),
                foreground="#4B0082",
                justify="center"
            )
            for line in summary.strip().splitlines():
                self.graph_text.insert(tk.END, line.strip() + "\n", "centered")
            self.graph_text.config(state=tk.DISABLED)
            self.graph_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
            self.graph_canvas.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    def bandwidth_speed_test(self):
        import time
        import random
        import requests

        witty_messages = [
            "Testing the speed of light... or at least your connection!",
            "Downloading at warp speed...",
            "Measuring bandwidth, please wait...",
            "Bits are flying, hang tight!",
            "Crunching numbers and packets...",
            "Speed test in progress, don't blink!",
            "Unleashing the bandwidth beast...",
            "Counting bytes faster than ever...",
            "Your network's pedal to the metal...",
            "Almost there, just a few more bits!"
        ]
        loading_anim = ["[=     ]", "[==    ]", "[===   ]", "[ ===  ]", "[  === ]", "[   ===]", "[    ==]", "[     =]", "[      ]"]

        host = self.entry.get().strip()
        if not host or host.lower() == "enter ip/domain to diagnose":
            self.update_graph_text(
                "Please enter a host or IP in the search bar.\n\n"
                "Tip: For a free public speed test, enter 'speed.hetzner.de'."
            )
            return

        # Always use speed.hetzner.de for the test, regardless of user input
        test_server = "http://speed.hetzner.de/100MB.bin"
        self.update_graph_text(
            "[Bandwidth Speed Test]\n\n"
            "Testing bandwidth to speed.hetzner.de (free public test server)...\n"
            "This server is provided for public speed testing and is free to use.\n\n"
            + random.choice(witty_messages) + "\n"
        )

        def speed_task():
            try:
                # --- Download Speed Test ---
                download_speed = None
                download_error = None
                try:
                    start = time.time()
                    resp = requests.get(test_server, stream=True, timeout=10)
                    if resp.status_code != 200:
                        download_error = f"HTTP {resp.status_code} from {test_server}"
                        raise Exception(download_error)
                    total = 0
                    chunk_size = 1024 * 64  # 64KB
                    anim_idx = 0
                    t0 = time.time()
                    for chunk in resp.iter_content(chunk_size=chunk_size):
                        total += len(chunk)
                        elapsed = time.time() - t0
                        anim = loading_anim[anim_idx % len(loading_anim)]
                        anim_idx += 1
                        mb = total / (1024 * 1024)
                        witty = random.choice(witty_messages)
                        self.update_graph_text(
                            f"[Bandwidth Speed Test]\n\nDownloading from: {test_server}\n"
                            f"Downloaded: {mb:.2f} MB\n"
                            f"{witty} {anim}\n"
                        )
                        if elapsed > 5:  # Download for 5 seconds max
                            break
                    resp.close()
                    end = time.time()
                    duration = end - start
                    if total > 0 and duration > 0:
                        download_speed = (total * 8) / (duration * 1024 * 1024)
                except Exception as e:
                    download_speed = None
                    download_error = str(e)

                # --- Upload Speed Test (optional, can be skipped or left as is) ---
                upload_speed = None
                try:
                    self.update_graph_text(
                        "[Bandwidth Speed Test]\n\nTesting upload speed...\n" + random.choice(witty_messages)
                    )
                    data = b"x" * (1024 * 1024 * 5) # 5MB
                    t0 = time.time()
                    anim_idx = 0
                    for i in range(5):
                        chunk = b"x" * (1024 * 1024)  # 1MB
                        resp = requests.post("https://httpbin.org/post", data=chunk, timeout=10)
                        anim = loading_anim[anim_idx % len(loading_anim)]
                        anim_idx += 1
                        witty = random.choice(witty_messages)
                        self.update_graph_text(
                            f"[Bandwidth Speed Test]\n\nUploading chunk {i+1}/5...\n"
                            f"{witty} {anim}\n"
                        )
                    t1 = time.time()
                    duration = t1 - t0
                    if duration > 0:
                        upload_speed = (5 * 1024 * 1024 * 8) / (duration * 1024 * 1024)
                except Exception:
                    upload_speed = None

                # --- Results ---
                result = "[Bandwidth Speed Test]\n\n"
                result += f"Tested bandwidth to: {test_server}\n"
                if download_speed:
                    result += f"Download Speed: {download_speed:.2f} Mbps\n"
                else:
                    result += f"Download speed test failed. {download_error}\n"
                if upload_speed:
                    result += f"Upload Speed: {upload_speed:.2f} Mbps\n"
                else:
                    result += "Upload speed test failed.\n"
                result += random.choice(witty_messages)
                self.update_graph_text(result)

            except Exception as e:
                self.update_graph_text(f"[Bandwidth Speed Test]\n\nError: {e}")

        threading.Thread(target=speed_task, daemon=True).start()  # <-- ADD THIS LINE

    def stop_all(self):
        self.stop_all_flag = True
        self.pinggraph_running = False
        self.portscan_running = False
        self.speedtest_running = False
        self.pinggraph_toggle_button.config(text="Start Ping Graph")
        witty_lines = [
            "🦾 Network engineers: turning chaos into connectivity since forever.",
            "🧑‍💻 If it works, don't touch it. If it doesn't, blame the firewall.",
            "🛰️ Real heroes don't wear capes—they configure routers.",
            "🦄 Network magic: When a cable wiggle fixes everything.",
            "🕵️‍♂️ Diagnosing networks: 10% skill, 90% ping.",
            "🌐 If you can read this, thank a network engineer.",
            "🧙‍♂️ Network engineers: Wizards of the wire.",
            "🚦 Red light, green light—network traffic edition.",
            "🧩 Subnetting: Because one network is never enough.",
            "🦉 Wise network tip: Always check the physical layer first.",
            "🔌 Unplugged it and plugged it back in? Certified engineer move.",
            "🛠️ Network engineers: Making the internet less mysterious, one packet at a time.",
            "📡 When in doubt, blame DNS.",
            "🧬 Networking: Where every bit counts and every byte bites.",
            "🦥 Slow network? Time for a coffee break (or two).",
            "🦾 Automation is great—until you automate a typo.",
            "🧑‍🔧 Network engineers: The real backbone of the digital world.",
            "🦄 If only networks fixed themselves as fast as you can ping.",
            "🧙‍♂️ Network spells: 'show run', 'ping', and 'why is this down?'",
            "🧑‍💻 Behind every great connection is a network engineer who didn't give up.",
        ]
        witty = random.choice(witty_lines)
        banner = (
            "\n\n"
            "© Network Utility By Arunim\n"
            + "-" * 55 + "\n"
            f"{witty}\n"
            "All running operations stopped. You can start a new diagnosis anytime!\n"
        )
        if hasattr(self, "_last_ping_stats") and self._last_ping_stats:
            text = f"{banner}\n{self._last_ping_stats}"
        else:
            text = f"{banner}"

        # Center all text in the canvas
        self.graph_text.config(state=tk.NORMAL)
        self.graph_text.delete("1.0", tk.END)
        self.graph_text.tag_configure(
            "centered",
            font=("Comic Sans MS", 16, "bold"),
            foreground="#4B0082",
            justify="center"
        )
        # Insert each line centered
        for line in text.strip().splitlines():
            self.graph_text.insert(tk.END, line.strip() + "\n", "centered")
        self.graph_text.config(state=tk.DISABLED)

    def reset_canvas(self):
        self.graph_text.config(state=tk.NORMAL)
        self.graph_text.delete("1.0", tk.END)
        self.entry.delete(0, tk.END)
        self.show_watermark()

    def divide_subnet(self):
        import ipaddress
        import tkinter.simpledialog as sd

        witty_errors = [
            "Subnetting wizard says: That's too many slices! 🍕",
            "Oops! Even IPv6 would blush at that request. 😅",
            "Subnet math error: You can't cut a pizza into negative slices! 🍕",
            "Sorry, that's more subnets than atoms in the universe. 🌌",
            "Subnetting failed: Not even Chuck Norris can divide it that way! 🥋",
            "Subnet error: That's like trying to split a hair with a chainsaw. ✂️",
            "Subnetting fail: The network gnomes are confused. 🧙‍♂️",
            "Subnetting error: That's a subnet too far! 🚀"
        ]

        # Ask user for subnet and number of subnets
        subnet = self.entry.get().strip()
        if not subnet:
            subnet = sd.askstring("Divide Subnet", "Enter network (e.g. 192.168.1.0/24):")
            if not subnet:
                self.update_graph_text("No subnet entered.")
                return
        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except Exception as e:
            self.update_graph_text(f"Invalid network: {e}")
            return

        num = sd.askinteger("Divide Subnet", "How many subnets do you want?")
        if not num or num < 1:
            self.update_graph_text("Invalid number of subnets.")
            return

        try:
            subnets = list(network.subnets(new_prefix=network.prefixlen + (num-1).bit_length()))
            if len(subnets) < num:
                self.update_graph_text("Cannot divide into that many subnets.")
                return
            result = f"Dividing {network} into {num} subnets:\n\n"
            for i, sn in enumerate(subnets[:num], 1):
                result += f"{i}. {sn}\n"
            self.update_graph_text(result)
        except Exception:
            import random
            self.update_graph_text(random.choice(witty_errors))

    def generate_network_health_report(self):
        import threading
        import platform
        import subprocess
        import socket
        import requests
        from datetime import datetime
        import os
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas as pdf_canvas
        import time
        import random
        import matplotlib.pyplot as plt

        witty_lines = [
            "🛰️ Gathering packets from the digital ether...",
            "🕵️‍♂️ Sniffing out open ports like a network detective...",
            "🌐 Did you know? The first message sent over ARPANET was 'LO' (they meant to type 'LOGIN')!",
            "From complexity to clarity — Arunim helps teams rise above.",
            "📡 Pinging the internet's heartbeat...",
            "💡 Fun fact: The word 'ping' comes from sonar technology!",
            "🧑‍💻 Counting your packets so you don't have to.",
            "Every time you doubt yourself, remember: Arunim was made to rise.",
            "Bringing solutions with calm confidence — the Arunim standard.",
            "🦾 Assembling your network health dossier...",
            "🧙‍♂️ Summoning the spirits of TCP/IP...",
            "🦉 Wise tip: Open ports are like open doors. Keep only what you need!",
            "🦄 Networking is magic, but this report is real.",
            "🚦 Checking your network traffic lights...",
            "🧬 Networking fact: IPv6 has enough addresses for every grain of sand on Earth... and more!"
        ]

        host = self.entry.get().strip()
        if not host:
            self.show_text()
            self.update_graph_text("Please enter a host or IP for the health report.")
            return

        self.show_text()
        self.update_graph_text(
            "[Network Health Report]\n\n" +
            random.choice(witty_lines) +
            "\n\nGenerating report and PDF...\n(This may take a few seconds)"
        )

        def report_task():
            try:
                for i in range(3):
                    self.show_text()
                    self.update_graph_text(
                        "[Network Health Report]\n\n" +
                        random.choice(witty_lines) +
                        "\n\nGenerating report and PDF...\nPlease wait..."
                    )
                    time.sleep(1.2)

                ip = host
                try:
                    ip = socket.gethostbyname(host)
                except Exception:
                    pass

                report = []
                now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                report.append(f"Network Health Report for: {host} ({ip})")
                report.append(f"Report generated on: {now}")
                report.append("Platform: " + platform.platform())
                report.append("")

                # 1. Public IP check
                try:
                    public_ip = requests.get("https://api.ipify.org").text
                    report.append(f"Public IP: {public_ip}")
                except Exception:
                    report.append("Public IP: Unable to determine")

                # 2. Ping details and collect ping data for graph
                report.append("")
                report.append("Ping Details:")
                ping_values = []
                try:
                    if platform.system().lower() == "windows":
                        cmd = ["ping", "-n", "10", ip]
                    else:
                        cmd = ["ping", "-c", "10", ip]
                    output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.STDOUT)
                    report.append(output)
                    # Extract ping times for graph
                    import re
                    for line in output.splitlines():
                        match = re.search(r'time[=<]?\s*([\d\.]+)\s*ms', line)
                        if match:
                            ping_values.append(float(match.group(1)))
                except Exception as e:
                    report.append(f"Ping failed: {e}")

                # 3. Traceroute (up to 5 hops)
                report.append("")
                report.append("Traceroute (up to 5 hops):")
                try:
                    if platform.system().lower() == "windows":
                        command = ["tracert", "-h", "5", ip]
                    else:
                        command = ["traceroute", "-m", "5", ip]
                    output = subprocess.check_output(command, universal_newlines=True, stderr=subprocess.STDOUT)
                    report.append(output)
                except Exception as e:
                    report.append(f"Traceroute failed: {e}")

                # 4. Open ports scan (top 10 common ports)
                report.append("")
                report.append("Open Ports Scan (top 10 common ports):")
                common_ports = [22, 80, 443, 21, 23, 25, 53, 110, 135, 139]
                open_ports = []
                for port in common_ports:
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                            sock.settimeout(1)
                            result = sock.connect_ex((ip, port))
                            if result == 0:
                                open_ports.append(port)
                    except Exception:
                        pass
                if open_ports:
                    report.append("Open ports: " + ", ".join(str(p) for p in open_ports))
                else:
                    report.append("No open ports found in the common range.")

                # 5. DNS resolution
                report.append("")
                report.append("DNS Resolution:")
                try:
                    hostname, _, _ = socket.gethostbyaddr(ip)
                    report.append(f"Reverse DNS: {hostname}")
                except Exception:
                    report.append("Reverse DNS: Not available")
                try:
                    ip_address = socket.gethostbyname(host)
                    report.append(f"Forward DNS: {ip_address}")
                except Exception:
                    report.append("Forward DNS: Not available")

                # 6. Network interfaces and IPs
                report.append("")
                report.append("Network Interfaces and IPs:")
                try:
                    if platform.system().lower() == "windows":
                        interfaces = subprocess.check_output(["ipconfig"], universal_newlines=True)
                    else:
                        interfaces = subprocess.check_output(["ifconfig"], universal_newlines=True)
                    report.append(interfaces)
                except Exception as e:
                    report.append(f"Error getting network interfaces: {e}")

                # 7. Active connections
                report.append("")
                report.append("Active Connections:")
                try:
                    if platform.system().lower() == "windows":
                        connections = subprocess.check_output(["netstat", "-ano"], universal_newlines=True)
                    else:
                        connections = subprocess.check_output(["netstat", "-tunap"], universal_newlines=True)
                    report.append(connections)
                except Exception as e:
                    report.append(f"Error getting active connections: {e}")

                # 8. Geo Location
                report.append("")
                report.append("Geo Location:")
                try:
                    response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        geo_report = (
                            f"IP: {data.get('ip', 'N/A')}\n"
                            f"Hostname: {data.get('hostname', 'N/A')}\n"
                            f"City: {data.get('city', 'N/A')}\n"
                            f"Region: {data.get('region', 'N/A')}\n"
                            f"Country: {data.get('country', 'N/A')}\n"
                            f"Location: {data.get('loc', 'N/A')}\n"
                            f"Org/ASN: {data.get('org', 'N/A')}\n"
                            f"Timezone: {data.get('timezone', 'N/A')}\n"
                        )
                        report.append(geo_report)
                    else:
                        report.append("Geo info not found.")
                except Exception as e:
                    report.append(f"Geo lookup failed: {e}")

                # Add a random networking fact at the end
                report.append("")
                report.append("Fun Networking Fact:")
                report.append(random.choice(witty_lines))

                # Compile report
                full_report = "\n".join(report)

                # --- Draw ping graph on canvas ---
                if ping_values:
                    self.pings = ping_values[-self.max_points:]
                    self.draw_ping_graph()
                    self.show_graph_and_text(full_report)
                else:
                    self.show_text()
                    self.update_graph_text(full_report)

                # --- PDF Generation with ping graph ---
                try:
                    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
                    if not os.path.exists(desktop):
                        desktop = tempfile.gettempdir()
                    pdf_filename = f"NetworkHealthReport_{host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                    pdf_path = os.path.join(desktop, pdf_filename)

                    doc = SimpleDocTemplate(pdf_path, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
                    styles = getSampleStyleSheet()
                    if 'SectionHeader' not in styles:
                        styles.add(ParagraphStyle(name='SectionHeader', fontSize=15, leading=20, textColor=colors.HexColor("#005a9e"), spaceAfter=10, spaceBefore=16, fontName="Helvetica-Bold"))
                    if 'SubHeader' not in styles:
                        styles.add(ParagraphStyle(name='SubHeader', fontSize=12, leading=16, textColor=colors.HexColor("#228b22"), spaceAfter=6, fontName="Helvetica-Bold"))
                    if 'Normal' not in styles:
                        styles.add(ParagraphStyle(name='Normal', fontSize=10, leading=14, textColor=colors.HexColor("#23272e"), fontName="Helvetica"))
                    if 'Geo' not in styles:
                        styles.add(ParagraphStyle(name='Geo', fontSize=10, leading=14, textColor=colors.HexColor("#4B0082"), fontName="Helvetica-Oblique"))
                    if 'Footer' not in styles:
                        styles.add(ParagraphStyle(name='Footer', fontSize=9, leading=12, textColor=colors.HexColor("#4B0082"), fontName="Helvetica-Oblique", alignment=TA_CENTER))
                    if 'Fact' not in styles:
                        styles.add(ParagraphStyle(name='Fact', fontSize=11, leading=15, textColor=colors.HexColor("#ff8800"), fontName="Helvetica-Oblique"))

                    elements = []
                    elements.append(Paragraph("Network Health Report", styles['SectionHeader']))
                    elements.append(Paragraph(f"Host: {host} ({ip})<br/>Generated: {now}", styles['Normal']))
                    elements.append(Spacer(1, 12))

                    # Insert ping graph image if available
                    if ping_values:
                        graph_path = os.path.join(tempfile.gettempdir(), f"ping_graph_{random.randint(1000,9999)}.png")
                        import matplotlib.pyplot as plt
                        plt.figure(figsize=(6, 2.5))
                        plt.plot(ping_values, marker='o', color='blue')
                        plt.title("Ping Latency Graph")
                        plt.xlabel("Sample")
                        plt.ylabel("Latency (ms)")
                        plt.grid(True)
                        plt.tight_layout()
                        plt.savefig(graph_path)
                        plt.close()
                        elements.append(Image(graph_path, width=400, height=120))
                        elements.append(Spacer(1, 16))

                    # Helper to add sections
                    def add_section(title, content, style='SectionHeader', normal_style='Normal'):
                        elements.append(Paragraph(title, styles[style]))
                        if isinstance(content, list):
                            for line in content:
                                if line:
                                    elements.append(Paragraph(str(line).replace('\n', '<br/>'), styles[normal_style]))
                        else:
                            if content:
                                elements.append(Paragraph(str(content).replace('\n', '<br/>'), styles[normal_style]))
                        elements.append(Spacer(1, 8))

                    # Parse and add each section
                    def extract_section(lines, header):
                        idx = [i for i, l in enumerate(lines) if l.strip() == header]
                        if not idx:
                            return []
                        start = idx[0] + 1
                        end = next((i for i in range(start, len(lines)) if lines[i].strip() == ""), len(lines))
                        return lines[start:end]

                    lines = full_report.splitlines()
                    add_section("Public IP", extract_section(lines, "Public IP:"), style='SubHeader')
                    add_section("Ping Details", extract_section(lines, "Ping Details:"), style='SubHeader')
                    add_section("Traceroute (up to 5 hops)", extract_section(lines, "Traceroute (up to 5 hops):"), style='SubHeader')
                    add_section("Open Ports Scan (top 10 common ports)", extract_section(lines, "Open Ports Scan (top 10 common ports):"), style='SubHeader')
                    add_section("DNS Resolution", extract_section(lines, "DNS Resolution:"), style='SubHeader')
                    add_section("Network Interfaces and IPs", extract_section(lines, "Network Interfaces and IPs:"), style='SubHeader')
                    add_section("Active Connections", extract_section(lines, "Active Connections:"), style='SubHeader')
                    geo_lines = extract_section(lines, "Geo Location:")
                    if geo_lines:
                        add_section("Geo Location", geo_lines, style='SubHeader', normal_style='Geo')
                    fact_idx = [i for i, l in enumerate(lines) if l.strip() == "Fun Networking Fact:"]
                    if fact_idx:
                        fact = lines[fact_idx[0]+1] if len(lines) > fact_idx[0]+1 else ""
                        elements.append(Paragraph("Fun Networking Fact", styles['Fact']))
                        elements.append(Paragraph(fact, styles['Fact']))

                    elements.append(Spacer(1, 16))
                    elements.append(Paragraph("© Network Utility by Arunim Pandey", styles['Footer']))

                    # Full Raw Report section
                    elements.append(Spacer(1, 24))
                    elements.append(Paragraph("Full Raw Report (as shown on canvas):", styles['SectionHeader']))
                    elements.append(Preformatted(full_report, styles['Normal']))

                    doc.build(elements)

                    # Show status and open PDF
                    self.show_text()
                    self.update_graph_text(
                        full_report +
                        f"\n\nNetwork Health Report generated!\nSaved to:\n{pdf_path}\n\n"
                        "The PDF will open automatically.\n\n"
                        + random.choice(witty_lines)
                    )
                    try:
                        import webbrowser
                        webbrowser.open(pdf_path)
                    except Exception:
                        pass
                except Exception as e:
                    self.show_text()
                    self.update_graph_text(full_report + f"\n\nFailed to generate PDF: {e}")

            except Exception as e:
                self.show_text()
                self.update_graph_text(f"Failed to generate report:\n{e}")

        threading.Thread(target=report_task, daemon=True).start()

    def show_canvas(self):
        self.graph_text.pack_forget()
        self.graph_canvas.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        # Remove axes from the ping graph when switching to canvas (functional button clicked)
        self.graph_canvas.delete("all")

    def show_text(self):
        self.graph_canvas.pack_forget()
        self.graph_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        self.graph_text.config(state=tk.NORMAL)
        self.graph_text.delete("1.0", tk.END)
        self.graph_text.config(state=tk.DISABLED)

    def show_graph_and_text(self, text):
        self.graph_canvas.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        self.graph_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        self.graph_text.config(state=tk.NORMAL)
        self.graph_text.delete("1.0", tk.END)
        self.graph_text.insert(tk.END, text)
        self.graph_text.config(state=tk.DISABLED)

    def show_route_table(self):
        host = self.entry.get().strip()
        if not host or host.lower() == "enter ip/domain to diagnose":
            self.update_graph_text("Please enter a host or IP in the search bar.")
            return
        self.update_graph_text("This process could take a few seconds...\nFetching route table, please wait...")

        def route_task():
            if platform.system().lower() == "windows":
                command = ["route", "print"]
            else:
                command = ["netstat", "-rn"]
            try:
                output = subprocess.check_output(command, universal_newlines=True, stderr=subprocess.STDOUT)
            except Exception as e:
                output = f"Failed to get route table:\n{e}"
            self.update_graph_text(output)
        threading.Thread(target=route_task, daemon=True).start()

    def show_technical_documentation(self):
        self.show_text()
        self.graph_text.config(state=tk.NORMAL)
        self.graph_text.delete("1.0", tk.END)

        # Set a consistent, readable font for all text in the canvas
        self.graph_text.configure(font=("Segoe UI", 12), spacing1=2, spacing3=4)

        # Tag configuration for styling
        self.graph_text.tag_configure("banner", font=("Comic Sans MS", 22, "bold"), foreground="#ffffff", background="#4B0082", justify="center", spacing3=12, lmargin1=0, lmargin2=0)
        self.graph_text.tag_configure("heading", font=("Segoe UI", 16, "bold"), foreground="#4B0082", spacing3=8)
        self.graph_text.tag_configure("subheading", font=("Segoe UI", 13, "bold"), foreground="#005a9e", spacing3=4)
        self.graph_text.tag_configure("command", font=("Consolas", 12, "bold"), foreground="#228b22", background="#f0f0f0")
        self.graph_text.tag_configure("note", font=("Segoe UI", 12, "italic"), foreground="#b22222")
        self.graph_text.tag_configure("normal", font=("Segoe UI", 12), foreground="#23272e")
        self.graph_text.tag_configure("bullet", font=("Segoe UI", 12), foreground="#007acc")
        self.graph_text.tag_configure("footer", font=("Segoe UI", 10, "italic"), foreground="#4B0082")
        self.graph_text.tag_configure("link", foreground="#005a9e", underline=True, font=("Segoe UI", 12, "underline"))

        def insert(text, tag="normal"):
            self.graph_text.insert(tk.END, text + "\n", tag)

        # Reference links for the bottom section (updated for retired docs)
        reference_links = [
            ("GeekForGeeks: IPv4 Overview", "https://www.geeksforgeeks.org/what-is-ipv4/"),
            ("GeekForGeeks: IPv6 Overview", "https://www.geeksforgeeks.org/what-is-ipv6/"),
            ("Microsoft Docs: Ping Command", "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ping"),
            ("Microsoft Docs: Tracert Command", "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tracert"),
            ("Microsoft Docs: Netstat Command", "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat"),
            ("Microsoft Docs: Route Print", "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/route_ws2008"),
        ]

        # Banner and main content as before...
        insert(" Network Utility by Arunim Pandey ", "banner")
        insert("Technical SOP & Documentation", "heading")
        insert("Version: 1.4.2 (Revised) Release — Date: 30 June 2025", "footer")
        insert("")
        insert("1. Product Overview", "subheading")
        insert("Network Utility is a Windows-based GUI application for advanced network diagnostics, troubleshooting, and reporting.", "normal")
        insert("It consolidates essential network engineering tools into a single interface, supporting real-time monitoring, multi-layer diagnostics, and automated reporting for any IPv4/IPv6 address or FQDN.", "normal")
        insert("")
        insert("2. System Requirements", "subheading")
        insert("• OS: Windows 10/11, Windows Server 2012–2022", "bullet")
        insert("• Python: 3.8+ (for source version)", "bullet")
        insert("• Dependencies: requests, reportlab, tkinter (standard with Python)", "bullet")
        insert("• Privileges: Administrator recommended for full netstat/route access", "bullet")
        insert("• Network: Internet required for GeoIP, ASN, and speed test features", "bullet")
        insert("")
        insert("3. Installation", "subheading")
        insert("A. Standalone Executable:", "normal")
        insert("   - Download the .exe file and double-click to launch. No Python required.", "normal")
        insert("B. From Source:", "normal")
        insert("   1. Install Python 3.8+ from python.org", "normal")
        insert("   2. Install dependencies:", "normal")
        insert("      pip install requests reportlab", "command")
        insert("   3. Run:", "normal")
        insert("      python src/main.py", "command")
        insert("")
        insert("4. Functional Overview", "subheading")
        insert("All diagnostics and reports are scoped to the IP/domain entered in the search bar.", "note")
        insert("Buttons:", "normal")
        insert("  - Send Ping: ICMP echo request to target. Live RTT, packet loss, summary stats.", "bullet")
        insert("  - Show Route Table: Displays local routing table (route print/netstat -rn).", "bullet")
        insert("  - Geo & ASN Lookup: Queries public APIs for geolocation and ASN data.", "bullet")
        insert("  - Show Next Hops: Traceroute (5 hops) to target.", "bullet")
        insert("  - Advanced Packet Capture: Shows active TCP/UDP connections for the target.", "bullet")
        insert("  - Port Scan Capture: TCP connect scan of all ports. Live progress.", "bullet")
        insert("  - Bandwidth Speed Test: Download/upload speed using speed.hetzner.de.", "bullet")
        insert("  - Start Ping Graph: Real-time RTT plot for the target.", "bullet")
        insert("  - Divide Subnet: Splits entered CIDR into user-defined subnets.", "bullet")
        insert("  - Auto Network Health Report (PDF): Aggregates diagnostics into a PDF report.", "bullet")
        insert("  - Reset Output & Input: Clears output and search bar.", "bullet")
        insert("  - Stop All Functions: Terminates all ongoing diagnostics and scans.", "bullet")
        insert("")
        insert("5. Operational Details", "subheading")
        insert("- Send Ping: Uses system ping utility. Aggregates min/avg/max RTT, packet loss.", "normal")
        insert("- Show Route Table: route print (Windows) or netstat -rn (Unix).", "normal")
        insert("- Geo & ASN Lookup: Uses ipinfo.io API. Requires internet.", "normal")
        insert("- Show Next Hops: tracert/traceroute for up to 5 hops.", "normal")
        insert("- Advanced Packet Capture: netstat -ano/-tunap, filtered for target.", "normal")
        insert("- Port Scan Capture: TCP connect scan on all ports (1–65535). May take several minutes.", "normal")
        insert("- Bandwidth Speed Test: Downloads 100MB from speed.hetzner.de. Upload via httpbin.org.", "normal")
        insert("- Start Ping Graph: Plots real-time RTT values.", "normal")
        insert("- Divide Subnet: Accepts CIDR, prompts for number of subnets, displays results.", "normal")
        insert("- Auto Network Health Report (PDF): Runs all diagnostics, generates PDF (Desktop).", "normal")
        insert("- Reset Output & Input: Clears output and search bar.", "normal")
        insert("- Stop All Functions: Halts all running threads and diagnostics.", "normal")
        insert("")
        insert("6. Best Practices & Notes", "subheading")
        insert("• Always enter a valid IP/domain before running any function.", "bullet")
        insert("• For accurate results, run as administrator.", "bullet")
        insert("• Use bandwidth and port scan features responsibly; avoid scanning unauthorized hosts.", "bullet")
        insert("• All diagnostics are performed on the entered target only—no local defaults.", "bullet")
        insert("• For support: arunimpandey2903@hotmail.com", "bullet")
        insert("")

        # Reference Articles Section
        insert("Reference Articles", "heading")
        for idx, (text, url) in enumerate(reference_links):
            tag = f"ref_link_{idx}"
            start_idx = self.graph_text.index(tk.END)
            self.graph_text.insert(tk.END, f"• {text}\n", ("link", tag))
            end_idx = self.graph_text.index(tk.END)
            # Remove trailing newline from tag range
            self.graph_text.tag_add(tag, start_idx, f"{end_idx} -1c")
            self.graph_text.tag_bind(tag, "<Button-1>", lambda e, link=url: webbrowser.open(link))

        self.graph_text.config(state=tk.DISABLED)

    def show_watermark(self):
        """Show watermark 'arunim' diagonally across the whole canvas if empty."""
        self.graph_text.config(state=tk.NORMAL)
        content = self.graph_text.get("1.0", tk.END).strip()
        if content:  # Only show watermark if empty
            self.graph_text.config(state=tk.DISABLED)
            return
        self.graph_text.tag_configure(
            "watermark",
            font=("Segoe UI", 36, "bold italic"),
            foreground="#f3f3fa"
        )
        lines = self.graph_text.winfo_height() // 32
        if lines < 10:
            lines = 20
        for i in range(2, lines, 2):
            spaces = " " * (i * 2)
            self.graph_text.insert(f"{i}.0", f"{spaces}arunim\n", "watermark")
        self.graph_text.tag_lower("watermark")
        self.graph_text.config(state=tk.DISABLED)

    def clear_watermark(self):
        """Remove watermark if present."""
        self.graph_text.config(state=tk.NORMAL)
        self.graph_text.tag_remove("watermark", "1.0", tk.END)
        self.graph_text.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkToolApp(root)
    root.mainloop()
