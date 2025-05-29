import tkinter as tk
from network.ping import ping_host
import threading
import subprocess
import platform
import requests
import socket
import os
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas as pdf_canvas

class ToolTip:
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
        x = x + self.widget.winfo_rootx() + 25
        y = y + cy + self.widget.winfo_rooty() + 25
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                         background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                         font=("tahoma", "10", "normal"))
        label.pack(ipadx=1)
    def hide_tip(self, event=None):
        tw = self.tipwindow
        self.tipwindow = None
        if tw:
            tw.destroy()

class NetworkToolApp:
    def __init__(self, master):
        self.master = master
        self.master.title("GUI Network Tool")
        self.master.geometry("900x650")

        # Main vertical layout: header, content (left/right), footer
        self.header = tk.Label(
            self.master,
            text="Network Utility",
            font=("Comic Sans MS", 22, "bold"),
            fg="#4B0082",
            bg="#E0E7FF",
            pady=10,
            justify="center",
            anchor="center"
        )
        self.header.pack(side=tk.TOP, fill=tk.X, pady=(0, 10))

        self.content_frame = tk.Frame(self.master)
        self.content_frame.pack(fill=tk.BOTH, expand=True)

        # Left frame for buttons (fill vertically)
        self.left_frame = tk.Frame(self.content_frame, bg="#e6eaf0", bd=2, relief=tk.GROOVE, width=240)
        self.left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=False, padx=(10, 0), pady=10)
        self.left_frame.pack_propagate(False)  # Prevent shrinking

        # Right frame for canvas/output
        self.right_frame = tk.Frame(self.content_frame)
        self.right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=0, pady=10)

        # Centered search bar at the top of right frame
        self.search_frame = tk.Frame(self.right_frame, bg="#F0F8FF")
        self.search_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 10), anchor="center")
        self.entry = tk.Entry(
            self.search_frame,
            font=("Comic Sans MS", 16),
            bg="#FFF8DC",
            fg="#888888",  # Gray color for watermark
            relief=tk.GROOVE,
            bd=3,
            width=40,
            justify="center"
        )
        self.entry.pack(padx=10, pady=5, fill=tk.X, expand=True)

        # Watermark logic
        self.entry.insert(0, "Enter IP/domain to diagnose")
        self.entry_is_watermark = True

        def on_entry_focus_in(event):
            if self.entry_is_watermark:
                self.entry.delete(0, tk.END)
                self.entry.config(fg="#333333")
                self.entry_is_watermark = False

        def on_entry_focus_out(event):
            if not self.entry.get():
                self.entry.insert(0, "Enter IP/domain to diagnose")
                self.entry.config(fg="#888888")
                self.entry_is_watermark = True

        self.entry.bind("<FocusIn>", on_entry_focus_in)
        self.entry.bind("<FocusOut>", on_entry_focus_out)

        # Graph/output area in right frame
        self.graph_text = tk.Text(
            self.right_frame,
            bg="#ffffff",
            fg="#000000",
            font=("Consolas", 11),
            wrap=tk.NONE
        )
        self.graph_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        self.graph_text.config(state=tk.NORMAL)
        self.graph_text.delete("1.0", tk.END)
        self.graph_text.insert(tk.END, "")
        self.graph_text.config(state=tk.DISABLED)

        # Button style
        btn_style = {
            "font": ("Consolas", 12, "bold"),
            "bg": "#23272e",
            "fg": "#ffffff",
            "activebackground": "#3a4050",
            "activeforeground": "#ffffff",
            "relief": tk.RAISED,
            "bd": 2,
            "width": 22,
            "cursor": "hand2",
            "anchor": "w",
            "justify": "left",
            "padx": 10
        }

        # Create buttons in left_frame (vertical stack)
        self.send_button = tk.Button(self.left_frame, text="Send Ping", command=self.send_ping, **btn_style)
        self.route_button = tk.Button(self.left_frame, text="Show Route Table", command=self.show_route_table, **btn_style)
        self.geoasn_button = tk.Button(self.left_frame, text="Geo & ASN Lookup", command=self.show_geoasn, **btn_style)
        self.nexthop_button = tk.Button(self.left_frame, text="Show Next Hops", command=self.show_next_hops, **btn_style)
        self.pcap_button = tk.Button(self.left_frame, text="Advanced Packet Capture", command=self.advanced_packet_capture, **btn_style)
        self.portscan_button = tk.Button(self.left_frame, text="Port Scan Capture", command=self.port_scan_capture, **btn_style)
        self.speedtest_button = tk.Button(self.left_frame, text="Bandwidth Speed", command=self.bandwidth_speed_test, **btn_style)
        self.pinggraph_start_button = tk.Button(self.left_frame, text="Start Ping Graph", command=self.start_ping_graph, **btn_style)
        self.pinggraph_stop_button = tk.Button(self.left_frame, text="Stop Ping Graph", command=self.stop_ping_graph, state=tk.DISABLED, **btn_style)

        # Stop All button (red)
        stop_btn_style = btn_style.copy()
        stop_btn_style.update({
            "bg": "#b22222",
            "fg": "#fff",
            "activebackground": "#e57373"
        })
        self.stopall_button = tk.Button(self.left_frame, text="🛑 Stop All", command=self.stop_all, **stop_btn_style)

        # Reset button (green)
        reset_btn_style = btn_style.copy()
        reset_btn_style.update({
            "bg": "#228b22",
            "fg": "#fff",
            "activebackground": "#7be67b"
        })
        self.reset_button = tk.Button(self.left_frame, text="🔄 Reset", command=self.reset_canvas, **reset_btn_style)

        # Auto Network Health Report button
        self.health_report_button = tk.Button(
            self.left_frame,
            text="Auto Network Health Report",
            command=self.generate_network_health_report,
            bg="#005a9e",
            fg="#fff",
            activebackground="#007acc",
            font=("Consolas", 12, "bold"),
            width=22,
            relief=tk.RAISED,
            bd=2,
            cursor="hand2",
            anchor="w",
            justify="left",
            padx=10
        )

        # Pack all buttons vertically and stretch to fill left frame
        for btn in [
            self.send_button, self.route_button, self.geoasn_button, self.nexthop_button,
            self.pcap_button, self.portscan_button, self.speedtest_button,
            self.pinggraph_start_button, self.pinggraph_stop_button,
            self.stopall_button, self.reset_button, self.health_report_button
        ]:
            btn.pack(fill=tk.X, expand=True, pady=4, padx=6)

        # Tooltips for buttons (keep as before)
        ToolTip(self.send_button, "Ping the entered host or IP! 🏓")
        ToolTip(self.portscan_button, "Scan for open ports on the target! 🔍")
        ToolTip(self.pinggraph_start_button, "Start a real-time ping graph! 📈")
        ToolTip(self.speedtest_button, "Test your bandwidth speed! 🚀")
        ToolTip(self.reset_button, "Clear the canvas and search bar! 🧹")
        ToolTip(self.stopall_button, "Stop all running operations! 🛑")

        # Footer branding (always at the bottom)
        self.footer = tk.Label(
            self.master,
            text="Network Utility | © Written by Arunim Pandey",
            font=("Comic Sans MS", 11, "bold italic"),
            fg="#fff",
            bg="#4B0082",
            pady=8,
            bd=2,
            relief=tk.RIDGE
        )
        self.footer.pack(side=tk.BOTTOM, fill=tk.X)

    def send_ping(self):
        host = self.entry.get()
        if not host:
            return
        self.stop_all_flag = False  # Reset stop flag when starting
        self.update_graph_text("Pinging...\n")
        def ping_task():
            lines = []
            for i, line in enumerate(ping_host(host)):
                if self.stop_all_flag:
                    self.update_graph_text("Ping stopped by user.\n")
                    break
                lines.append(line)
                if i > 20: break
                self.update_graph_text("".join(lines))
        threading.Thread(target=ping_task, daemon=True).start()

    def show_route_table(self):
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

    def show_geoasn(self):
        host = self.entry.get()
        if not host:
            self.update_graph_text("Please enter a host or IP.")
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
        host = self.entry.get()
        if not host:
            self.update_graph_text("Please enter a host or IP.")
            return
        self.update_graph_text("This process could take a few seconds...\nFetching next hops (up to 5)...")

        def nexthop_task():
            try:
                try:
                    ip = socket.gethostbyname(host)
                except Exception:
                    ip = host
                if platform.system().lower() == "windows":
                    command = ["tracert", "-h", "5", ip]
                else:
                    command = ["traceroute", "-m", "5", ip]
                output = subprocess.check_output(command, universal_newlines=True, stderr=subprocess.STDOUT)
            except Exception as e:
                output = f"Failed to get next hops:\n{e}"
            self.update_graph_text(output)
        threading.Thread(target=nexthop_task, daemon=True).start()

    def advanced_packet_capture(self):
        host = self.entry.get().strip()
        self.update_graph_text(
            "[Advanced Packet Capture]\n\nCollecting active connections...\n(This may take a few seconds)"
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
                    display = "[Advanced Packet Capture]\n\nActive Connections\n\n" + "".join(output_lines)
                    self.update_graph_text(display)

                if host:
                    filtered = [l for l in output_lines if ip in l or l.lower().startswith("proto") or l.lower().startswith("tcp") or l.lower().startswith("udp")]
                    if filtered and len(filtered) > 3:
                        display = "[Advanced Packet Capture]\n\nActive Connections\n\n" + "".join(filtered)
                    else:
                        display = "[Advanced Packet Capture]\n\nNo active connections found for {}.\n\nFull netstat output:\n\n".format(host) + "".join(output_lines)
                    self.update_graph_text(display)
                else:
                    display = "[Advanced Packet Capture]\n\nActive Connections\n\n" + "".join(output_lines)
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
                f"Total closed ports: {closed_ports}\n"
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
        self.stop_all_flag = False
        self.pinggraph_running = True
        import random
        import re

        host = self.entry.get().strip()
        if not host:
            self.graph_text.config(state=tk.NORMAL)
            self.graph_text.delete("1.0", tk.END)
            self.graph_text.insert(tk.END, "Please enter a host or IP.")
            self.graph_text.config(state=tk.DISABLED)
            return

        witty_messages = [
            "Measuring the speed of light... or at least your WiFi! 🚀",
            "Counting milliseconds like a caffeinated squirrel 🐿️",
            "Waiting for the echo... echo... echo... 🪩",
            "Ping pong with the network 🏓",
            "Timing those packets... 🕒",
            "Drawing the graph, hang tight! 🎨",
            "Network ninja at work 🥷",
            "Is it lag or just suspense? 😅",
            "Plotting your network's heartbeat... 💓",
            "Ping in progress, don't blink! 👀",
            "Packets are dancing! 💃🕺",
            "Internet hamster is running... 🐹💨"
        ]

        self.pinggraph_start_button.config(state=tk.DISABLED)
        self.pinggraph_stop_button.config(state=tk.NORMAL)
        self.graph_text.config(state=tk.NORMAL)
        self.graph_text.delete("1.0", tk.END)
        self.graph_text.insert(tk.END, "[Visual Ping Graph]\n\nPinging host, please wait...\n")
        self.graph_text.config(state=tk.DISABLED)

        def ping_task():
            import platform
            import subprocess
            import time
            import tkinter.font as tkFont

            try:
                ip = socket.gethostbyname(host)
            except Exception:
                ip = host

            pings = []
            count = 0

            # Dynamically set graph width based on widget size
            widget_width = self.graph_text.winfo_width()
            font = self.graph_text.cget("font")
            font_obj = tkFont.Font(font=font)
            char_width = font_obj.measure("0")
            graph_width = max(30, int(widget_width / (char_width if char_width else 8)) - 15)
            graph_height = 15

            # Setup color tags
            self.graph_text.tag_configure("low", foreground="#39C800")    # green
            self.graph_text.tag_configure("med", foreground="#FFD700")    # yellow
            self.graph_text.tag_configure("high", foreground="#FF5555")   # red
            self.graph_text.tag_configure("axis", foreground="#888888")   # gray
            self.graph_text.tag_configure("title", foreground="#005a9e", font=("Consolas", 13, "bold"))

            while self.pinggraph_running:
                count += 1
                witty = random.choice(witty_messages)
                if platform.system().lower() == "windows":
                    cmd = ["ping", "-n", "1", ip]
                else:
                    cmd = ["ping", "-c", "1", ip]
                try:
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                    output = proc.stdout
                    match = re.search(r'time[=<]?\s*([\d\.]+)\s*ms', output)
                    if match:
                        ms = float(match.group(1))
                        pings.append(ms)
                    else:
                        pings.append(None)
                except Exception as e:
                    pings.append(None)

                window = [v for v in pings[-graph_width:] if v is not None]
                graph_lines = []
                color_lines = []
                avg = sum(window) / len(window) if window else 0
                if window:
                    max_ping = max(window)
                    min_ping = min(window)
                    span = max_ping - min_ping if max_ping != min_ping else 1
                    grid = [[" " for _ in range(graph_width)] for _ in range(graph_height)]
                    color_grid = [["axis" for _ in range(graph_width)] for _ in range(graph_height)]
                    prev_y = None
                    for x, val in enumerate(window):
                        if val is not None:
                            y = int((val - min_ping) / span * (graph_height - 1))
                            y = graph_height - 1 - y
                            # Color code: green < 60ms, yellow < 150ms, red otherwise
                            if val < 60:
                                color = "low"
                            elif val < 150:
                                color = "med"
                            else:
                                color = "high"
                            grid[y][x] = "*"
                            color_grid[y][x] = color
                            if prev_y is not None:
                                y1, y2 = sorted([prev_y, y])
                                for yy in range(y1 + 1, y2):
                                    grid[yy][x - 1] = "|"
                                    color_grid[yy][x - 1] = color
                        prev_y = y
                for i, row in enumerate(grid):
                    label = f"{(max_ping - (span * i / (graph_height - 1))):7.2f} | "
                    graph_lines.append(label + "".join(row))
                    color_lines.append(["axis"] * (len(label)) + color_grid[i])
                x_axis = " " * 8 + "-" * graph_width
                graph_lines.append(x_axis)
                color_lines.append(["axis"] * len(x_axis))
                start_ping = len(pings) - len(window) + 1
                x_labels = " " * 8
                for i in range(graph_width):
                    if (i + start_ping) % 10 == 0:
                        x_labels += f"{(i + start_ping)%100:02d}"
                    else:
                        x_labels += "  "
                graph_lines.append(x_labels)
                color_lines.append(["axis"] * len(x_labels))
                graph_lines.append(f"Min: {min_ping:.2f} ms   Max: {max_ping:.2f} ms")
                color_lines.append(["axis"] * len(graph_lines[-1]))
            else:
                graph_lines.append("No successful pings yet.")
                color_lines.append(["axis"] * len(graph_lines[-1]))

            summary = f"\n{witty}\nTotal: {count} | Average: {avg:.2f} ms\n"
            banner_width = graph_width + 15
            title_text = "🖧 PING LATENCY GRAPH 🖧"
            pad_left = (banner_width - len(title_text)) // 2
            pad_right = banner_width - len(title_text) - pad_left
            title = (
                "║" + " " * pad_left + title_text + " " * pad_right + "║\n"
                "╚" + "═" * banner_width + "╝\n"
            )

            self.graph_text.config(state=tk.NORMAL)
            self.graph_text.delete("1.0", tk.END)
            self.graph_text.insert(tk.END, "[Visual Ping Graph]\n\n", "title")
            self.graph_text.insert(tk.END, title, "title")
            for line, tags in zip(graph_lines, color_lines):
                for char, tag in zip(line, tags):
                    self.graph_text.insert(tk.END, char, tag)
                self.graph_text.insert(tk.END, "\n")
            self.graph_text.insert(tk.END, summary, "axis")
            self.graph_text.config(state=tk.DISABLED)
            time.sleep(0.5)

        threading.Thread(target=ping_task, daemon=True).start()

    def stop_ping_graph(self):
        self.pinggraph_running = False
        self.pinggraph_start_button.config(state=tk.NORMAL)
        self.pinggraph_stop_button.config(state=tk.DISABLED)
        self.update_graph_text("Ping graph stopped.")

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
        # If the host is empty or local, use a public speed test server
        local_hosts = ["", "localhost", "127.0.0.1", "0.0.0.0"]
        if host.lower() in local_hosts:
            test_server = "https://speed.hetzner.de/100MB.bin"
            self.update_graph_text(
                "[Bandwidth Speed Test]\n\nTesting local machine internet speed using a public server...\n" +
                random.choice(witty_messages) + "\n"
            )
        else:
            # Try to use the host as a test server
            if not host.startswith("http"):
                test_server = f"http://{host}/100MB.bin"
            else:
                test_server = host.rstrip("/") + "/100MB.bin"
            self.update_graph_text(
                f"[Bandwidth Speed Test]\n\nTesting bandwidth to {host}...\n" +
                random.choice(witty_messages) + "\n"
            )

        def speed_task():
            try:
                # --- Download Speed Test ---
                download_speed = None
                download_error = None
                test_servers = [
                    "https://speed.hetzner.de/100MB.bin",
                    "https://speedtest.tele2.net/100MB.zip",
                    "http://ipv4.download.thinkbroadband.com/100MB.zip"
                ]
                # If user provided a remote host, try that first
                if host.lower() not in local_hosts:
                    test_servers.insert(0, test_server)
                for server in test_servers:
                    try:
                        start = time.time()
                        resp = requests.get(server, stream=True, timeout=10)
                        if resp.status_code != 200:
                            download_error = f"HTTP {resp.status_code} from {server}"
                            continue
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
                                f"[Bandwidth Speed Test]\n\nDownloading from: {server}\n"
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
                            break
                    except Exception:
                        continue

                # --- Upload Speed Test ---
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
                if host.lower() in local_hosts:
                    result += "Tested your local machine's internet speed using a public server.\n"
                if download_speed:
                    result += f"Download Speed: {download_speed:.2f} Mbps\n"
                else:
                    result += "Download speed test failed.\n"
                if upload_speed:
                    result += f"Upload Speed: {upload_speed:.2f} Mbps\n"
                else:
                    result += "Upload speed test failed.\n"
                result += random.choice(witty_messages)
                self.update_graph_text(result)

            except Exception as e:
                self.update_graph_text(f"[Bandwidth Speed Test]\n\nError: {e}")

        threading.Thread(target=speed_task, daemon=True).start()

    def stop_all(self):
        self.stop_all_flag = True
        self.pinggraph_running = False
        self.portscan_running = False
        self.speedtest_running = False
        self.pinggraph_start_button.config(state=tk.NORMAL)
        self.pinggraph_stop_button.config(state=tk.DISABLED)
        self.update_graph_text("🛑 All running operations stopped.")

    def reset_canvas(self):
        self.update_graph_text("")
        self.entry.delete(0, tk.END)

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

        witty_lines = [
            "🛰️ Gathering packets from the digital ether...",
            "🕵️‍♂️ Sniffing out open ports like a network detective...",
            "🌐 Did you know? The first message sent over ARPANET was 'LO' (they meant to type 'LOGIN')!",
            "🔍 Tracing routes like a cyber Sherlock Holmes...",
            "📡 Pinging the internet's heartbeat...",
            "💡 Fun fact: The word 'ping' comes from sonar technology!",
            "🧑‍💻 Counting your packets so you don't have to.",
            "🦑 Scanning ports like a digital octopus!",
            "🗺️ Mapping your network neighborhood...",
            "🦾 Assembling your network health dossier...",
            "🧙‍♂️ Summoning the spirits of TCP/IP...",
            "🦉 Wise tip: Open ports are like open doors. Keep only what you need!",
            "🦄 Networking is magic, but this report is real.",
            "🚦 Checking your network traffic lights...",
            "🧬 Networking fact: IPv6 has enough addresses for every grain of sand on Earth... and more!"
        ]

        host = self.entry.get().strip()
        if not host:
            self.update_graph_text("Please enter a host or IP for the health report.")
            return

        self.update_graph_text(
            "[Network Health Report]\n\n" +
            random.choice(witty_lines) +
            "\n\nGenerating report and PDF...\n(This may take a few seconds)"
        )

        def report_task():
            try:
                # Show witty lines while working
                for i in range(3):
                    self.update_graph_text(
                        "[Network Health Report]\n\n" +
                        random.choice(witty_lines) +
                        "\n\nGenerating report and PDF...\nPlease wait..."
                    )
                    time.sleep(1.2)

                # Resolve host to IP if possible
                ip = host
                try:
                    ip = socket.gethostbyname(host)
                except Exception:
                    pass  # If not resolvable, use as is

                report = []
                report.append(f"Network Health Report for: {host} ({ip})")
                now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                report.append(f"Report generated on: {now}")
                report.append("Platform: " + platform.platform())
                report.append("")

                # Public IP check
                try:
                    public_ip = requests.get("https://api.ipify.org").text
                    report.append(f"Public IP: {public_ip}")
                except Exception:
                    report.append("Public IP: Unable to determine")

                # Ping details
                report.append("")
                report.append("Ping Details:")
                try:
                    if platform.system().lower() == "windows":
                        cmd = ["ping", "-n", "4", ip]
                    else:
                        cmd = ["ping", "-c", "4", ip]
                    output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.STDOUT)
                    report.append(output)
                except Exception as e:
                    report.append(f"Ping failed: {e}")

                # Traceroute
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

                # Open ports scan (top 10 common ports)
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

                # DNS resolution
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

                # Network interfaces and IPs
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

                # Active connections
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

                # Geo Location
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
                self.update_graph_text(full_report)

                # --- PDF Generation ---
                try:
                    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
                    pdf_filename = f"NetworkHealthReport_{host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                    pdf_path = os.path.join(desktop, pdf_filename)
                    c = pdf_canvas.Canvas(pdf_path, pagesize=letter)
                    width, height = letter
                    y = height - 40

                    c.setFont("Helvetica-Bold", 16)
                    c.drawString(40, y, "Network Health Report")
                    y -= 30
                    c.setFont("Helvetica", 10)
                    c.drawString(40, y, f"Host: {host}   Date: {now}")
                    y -= 30

                    c.setFont("Helvetica", 9)
                    for line in full_report.splitlines():
                        if y < 50:
                            c.showPage()
                            y = height - 40
                            c.setFont("Helvetica", 9)
                        c.drawString(40, y, line)
                        y -= 12

                    c.save()
                    self.update_graph_text(
                        f"Network Health Report generated!\n\nSaved to:\n{pdf_path}\n\n"
                        "The PDF will open automatically.\n\n"
                        + random.choice(witty_lines)
                    )
                    # Open the PDF automatically
                    try:
                        import webbrowser
                        webbrowser.open(pdf_path)
                    except Exception:
                        pass
                except Exception as e:
                    self.update_graph_text(f"Failed to generate PDF: {e}")

            except Exception as e:
                self.update_graph_text(f"Failed to generate report:\n{e}")

        threading.Thread(target=report_task, daemon=True).start()

    def update_graph_text(self, text):
        self.graph_text.config(state=tk.NORMAL)
        self.graph_text.delete("1.0", tk.END)
        self.graph_text.insert(tk.END, text)
        self.graph_text.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkToolApp(root)
    root.mainloop()
