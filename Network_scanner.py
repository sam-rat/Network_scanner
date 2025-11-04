import scapy.all as scapy
import socket
import threading
from queue import Queue
import ipaddress
import tkinter as tk
from tkinter import ttk, messagebox

# --- Configurable parameters ---
PORTS_TO_SCAN = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080]
PORT_SCAN_TIMEOUT = 0.8
ICMP_TIMEOUT = 1.0
# ------------------------------------

def scan(ip, result_queue, progress_queue, total_ips):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answer = scapy.srp(packet, timeout=1, verbose=False)[0]

    clients = []
    for client in answer:
        client_info = {'IP': client[1].psrc, 'MAC': client[1].hwsrc}
        try:
            hostname = socket.gethostbyaddr(client_info['IP'])[0]
            client_info['Hostname'] = hostname
        except socket.herror:
            client_info['Hostname'] = 'Unknown'

        open_ports = []
        for port in PORTS_TO_SCAN:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(PORT_SCAN_TIMEOUT)
                err = s.connect_ex((client_info['IP'], port))
                if err == 0:
                    banner = None
                    try:
                        s.settimeout(0.6)
                        data = s.recv(1024)
                        if data:
                            banner = data.decode(errors='ignore').strip()
                    except Exception:
                        banner = None
                    open_ports.append({'port': port, 'banner': banner})
                s.close()
            except Exception:
                pass

        client_info['Open_Ports'] = open_ports
        try:
            resp = scapy.sr1(scapy.IP(dst=client_info['IP']) / scapy.ICMP(), timeout=ICMP_TIMEOUT, verbose=False)
            ttl = getattr(resp, 'ttl', None) if resp else None
            if ttl is None:
                client_info['OS'] = 'Unknown'
            elif ttl <= 64:
                client_info['OS'] = f'Linux/Unix (TTL={ttl})'
            elif ttl <= 128:
                client_info['OS'] = f'Windows-ish (TTL={ttl})'
            else:
                client_info['OS'] = f'Network device/Other (TTL={ttl})'
        except PermissionError:
            client_info['OS'] = 'Unknown (need elevated privileges)'
        except Exception:
            client_info['OS'] = 'Unknown'

        clients.append(client_info)

    result_queue.put(clients)
    progress_queue.put(1)  # Update progress


def print_result(clients):
    if not clients:
        print("No active hosts found.")
        return

    print("=" * 80)
    print(f"{'IP Address':<18}{'MAC Address':<22}{'Open Ports':<25}{'OS Guess':<15}")
    print("=" * 80)
    for client in clients:
        ip = client.get('IP', 'N/A')
        mac = client.get('MAC', 'N/A')
        ports = ', '.join(str(p['port']) for p in client.get('Open_Ports', [])) or '-'
        os_guess = client.get('OS', 'Unknown')
        print(f"{ip:<18}{mac:<22}{ports:<25}{os_guess:<15}")
    print("=" * 80)
    print(f"Total hosts found: {len(clients)}")
    print("=" * 80)


def main(cidr, progress_callback):
    results_queue = Queue()
    progress_queue = Queue()
    threads = []
    network = ipaddress.ip_network(cidr, strict=False)
    total_ips = len(list(network.hosts()))

    def progress_monitor():
        scanned = 0
        while scanned < total_ips:
            progress_queue.get()
            scanned += 1
            percent = int((scanned / total_ips) * 100)
            progress_callback(percent)
        progress_callback(100)

    threading.Thread(target=progress_monitor, daemon=True).start()

    for ip in network.hosts():
        thread = threading.Thread(target=scan, args=(str(ip), results_queue, progress_queue, total_ips))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    all_clients = []
    while not results_queue.empty():
        all_clients.extend(results_queue.get())

    print_result(all_clients)
    return all_clients


# ---------------- GUI ----------------

def run_gui():
    def update_progress(percent):
        progress_bar['value'] = percent
        progress_label.config(text=f"{percent}% completed")
        root.update_idletasks()

    def start_scan():
        cidr = cidr_entry.get().strip()
        if not cidr:
            messagebox.showwarning("Input Error", "Please enter a valid CIDR (e.g. 192.168.1.0/24)")
            return

        start_button.config(state='disabled')
        status_label.config(text="🔍 Scanning in progress...", bg="#ffb347")
        tree.delete(*tree.get_children())
        progress_bar['value'] = 0
        progress_label.config(text="0% completed")

        def thread_scan():
            results = main(cidr, update_progress)
            for c in results:
                ports = ', '.join(str(p['port']) for p in c.get('Open_Ports', [])) or '-'
                tree.insert('', 'end', values=(c['IP'], c['MAC'], ports, c['OS']))
            status_label.config(text=f"✅ Scan complete. {len(results)} hosts found.", bg="#77dd77")
            start_button.config(state='normal')

        threading.Thread(target=thread_scan, daemon=True).start()

    root = tk.Tk()
    root.title("🛰️ Network Scanner")
    root.geometry("880x600")
    root.configure(bg="#1e1e2e")

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview",
                    background="#2b2b3d", foreground="white",
                    fieldbackground="#2b2b3d", rowheight=26, font=('Segoe UI', 10))
    style.configure("Treeview.Heading",
                    background="#44475a", foreground="white", font=('Segoe UI', 10, 'bold'))
    style.map('Treeview', background=[('selected', '#6272a4')])

    title_label = tk.Label(root, text="Network Scanner", font=("Segoe UI", 20, "bold"),
                           fg="white", bg="#1e1e2e")
    title_label.pack(pady=15)

    frame = tk.Frame(root, bg="#1e1e2e")
    frame.pack(pady=5)

    tk.Label(frame, text="Enter Network CIDR: ", font=("Segoe UI", 12),
             fg="white", bg="#1e1e2e").pack(side='left', padx=5)
    cidr_entry = tk.Entry(frame, width=25, font=("Segoe UI", 12), bg="#3c3f41", fg="white",
                          insertbackground="white", relief="flat")
    cidr_entry.pack(side='left', padx=5, ipady=3)

    start_button = tk.Button(frame, text="Start Scan", font=("Segoe UI", 10, "bold"),
                             bg="#4CAF50", fg="white", activebackground="#45a049",
                             cursor="hand2", relief="flat", command=start_scan)
    start_button.pack(side='left', padx=8, ipadx=10, ipady=3)

    # Progress Bar
    progress_frame = tk.Frame(root, bg="#1e1e2e")
    progress_frame.pack(pady=10)
    progress_bar = ttk.Progressbar(progress_frame, orient='horizontal', length=400, mode='determinate')
    progress_bar.pack(pady=4)
    progress_label = tk.Label(progress_frame, text="0% completed", font=("Segoe UI", 10),
                              fg="white", bg="#1e1e2e")
    progress_label.pack()

    # Results Table
    columns = ("IP Address", "MAC Address", "Open Ports", "OS Guess")
    tree_frame = tk.Frame(root, bg="#1e1e2e")
    tree_frame.pack(fill='both', expand=True, padx=10, pady=10)
    tree_scroll = ttk.Scrollbar(tree_frame)
    tree_scroll.pack(side='right', fill='y')

    tree = ttk.Treeview(tree_frame, columns=columns, show='headings', yscrollcommand=tree_scroll.set)
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, width=200, anchor='center')
    tree.pack(fill='both', expand=True)
    tree_scroll.config(command=tree.yview)

    status_label = tk.Label(root, text="Ready", font=("Segoe UI", 10),
                            bg="#3c3f41", fg="white", anchor='w')
    status_label.pack(fill='x', side='bottom', pady=3)

    root.mainloop()


if __name__ == '__main__':
    run_gui()
