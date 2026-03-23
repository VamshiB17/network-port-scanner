import socket
import threading
import time
import queue
import sys
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from concurrent.futures import ThreadPoolExecutor

# ---------------------------
# Service Map
# ---------------------------
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    3306: 'MySQL', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt'
}

# ---------------------------
# Scanner Worker
# ---------------------------
class PortScanner:
    def __init__(self, target, start_port, end_port, timeout=0.5, max_workers=200):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.max_workers = max_workers

        self._stop_event = threading.Event()

        self.total_ports = max(0, end_port - start_port + 1)
        self.scanned_count = 0
        self.open_ports = []

        self._lock = threading.Lock()
        self.result_queue = queue.Queue()

    def stop(self):
        self._stop_event.set()

    def resolve_target(self):
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            raise Exception("Invalid hostname or unreachable target")

    def _scan_port(self, port):
        if self._stop_event.is_set():
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.target, port))

                if result == 0:
                    service = COMMON_PORTS.get(port, 'Unknown')
                    with self._lock:
                        self.open_ports.append((port, service))
                    self.result_queue.put(('open', port, service))

        except Exception as e:
            self.result_queue.put(('error', port, str(e)))

        finally:
            with self._lock:
                self.scanned_count += 1
                scanned = self.scanned_count

            self.result_queue.put(('progress', scanned, self.total_ports))

    def run(self):
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for port in range(self.start_port, self.end_port + 1):
                if self._stop_event.is_set():
                    break
                executor.submit(self._scan_port, port)

        self.result_queue.put(('done', None, None))


# ---------------------------
# GUI
# ---------------------------
class ScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Port Scanner")
        self.geometry("720x520")

        self.scanner = None
        self.scanner_thread = None
        self.start_time = None

        self._build_ui()

    def _build_ui(self):
        frm = ttk.LabelFrame(self, text="Scan Settings")
        frm.pack(fill="x", padx=10, pady=10)

        ttk.Label(frm, text="Target:").grid(row=0, column=0)
        self.ent_target = ttk.Entry(frm)
        self.ent_target.grid(row=0, column=1)

        ttk.Label(frm, text="Start Port:").grid(row=0, column=2)
        self.ent_start = ttk.Entry(frm, width=10)
        self.ent_start.insert(0, "1")
        self.ent_start.grid(row=0, column=3)

        ttk.Label(frm, text="End Port:").grid(row=0, column=4)
        self.ent_end = ttk.Entry(frm, width=10)
        self.ent_end.insert(0, "1024")
        self.ent_end.grid(row=0, column=5)

        self.btn_start = ttk.Button(frm, text="Start", command=self.start_scan)
        self.btn_start.grid(row=1, column=4)

        self.btn_stop = ttk.Button(frm, text="Stop", command=self.stop_scan, state="disabled")
        self.btn_stop.grid(row=1, column=5)

        # Status
        self.var_status = tk.StringVar(value="Idle")
        ttk.Label(self, textvariable=self.var_status).pack()

        self.progress = ttk.Progressbar(self, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=5)

        # Results
        self.txt = tk.Text(self)
        self.txt.pack(fill="both", expand=True)

        # Bottom
        frm2 = ttk.Frame(self)
        frm2.pack(fill="x")

        ttk.Button(frm2, text="Clear", command=self.clear).pack(side="left")
        self.btn_save = ttk.Button(frm2, text="Save", command=self.save, state="disabled")
        self.btn_save.pack(side="right")

    # -----------------------
    # Controls
    # -----------------------
    def start_scan(self):
        target = self.ent_target.get().strip()

        if not target:
            messagebox.showerror("Error", "Enter target")
            return

        try:
            start = int(self.ent_start.get())
            end = int(self.ent_end.get())
        except:
            messagebox.showerror("Error", "Ports must be numbers")
            return

        self.scanner = PortScanner(target, start, end)

        try:
            ip = self.scanner.resolve_target()
            self.append(f"Target: {target} ({ip})\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return

        # Disable inputs
        self.ent_target.config(state="disabled")
        self.ent_start.config(state="disabled")
        self.ent_end.config(state="disabled")

        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")

        self.start_time = time.time()

        self.scanner_thread = threading.Thread(target=self.scanner.run, daemon=True)
        self.scanner_thread.start()

        self.after(50, self.poll)

    def stop_scan(self):
        if self.scanner:
            self.scanner.stop()
            self.var_status.set("Stopping...")

    def clear(self):
        self.txt.delete("1.0", tk.END)

    def save(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if not path:
            return

        with open(path, "w") as f:
            for p, s in sorted(self.scanner.open_ports):
                f.write(f"{p} ({s})\n")

    # -----------------------
    # Helpers
    # -----------------------
    def append(self, text):
        self.txt.insert(tk.END, text)
        self.txt.see(tk.END)

    def poll(self):
        try:
            while True:
                msg, a, b = self.scanner.result_queue.get_nowait()

                if msg == 'open':
                    self.append(f"[+] {a} ({b}) open\n")

                elif msg == 'progress':
                    scanned, total = a, b

                    if scanned % 50 == 0 or scanned == total:
                        self.progress.config(maximum=total, value=scanned)
                        self.var_status.set(f"{scanned}/{total}")

                elif msg == 'done':
                    self.append("\nScan Complete\n")
                    self.append(f"Open Ports: {len(self.scanner.open_ports)}\n")

                    # Enable UI
                    self.btn_start.config(state="normal")
                    self.btn_stop.config(state="disabled")
                    self.btn_save.config(state="normal")

                    self.ent_target.config(state="normal")
                    self.ent_start.config(state="normal")
                    self.ent_end.config(state="normal")

        except queue.Empty:
            pass

        if self.scanner_thread.is_alive():
            self.after(50, self.poll)


# ---------------------------
# Main
# ---------------------------
def main():
    app = ScannerGUI()
    app.mainloop()

if __name__ == "__main__":
    main()