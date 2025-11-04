import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import threading
import platform


class NmapGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Nmap Scanner")
        self.root.geometry("800x600")

        # Variables
        self.target_var = tk.StringVar()
        self.scan_type_var = tk.StringVar(value="Quick Scan")
        self.ports_var = tk.StringVar(value="1-1000")
        self.output_var = tk.StringVar(value="Normal")

        # Create widgets
        self.create_widgets()

    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Target section
        target_frame = ttk.LabelFrame(main_frame, text="Target", padding="10")
        target_frame.pack(fill=tk.X, pady=5)

        ttk.Label(target_frame, text="Target (IP/Hostname/Range):").grid(row=0, column=0, sticky=tk.W)
        target_entry = ttk.Entry(target_frame, textvariable=self.target_var, width=40)
        target_entry.grid(row=0, column=1, sticky=tk.W, padx=5)

        # Scan options section
        options_frame = ttk.LabelFrame(main_frame, text="Scan Options", padding="10")
        options_frame.pack(fill=tk.X, pady=5)

        # Scan type
        ttk.Label(options_frame, text="Scan Type:").grid(row=0, column=0, sticky=tk.W)
        scan_types = ["Quick Scan", "Full Scan", "Ping Scan", "OS Detection", "Version Detection", "Custom"]
        scan_combo = ttk.Combobox(options_frame, textvariable=self.scan_type_var, values=scan_types, state="readonly")
        scan_combo.grid(row=0, column=1, sticky=tk.W, padx=5)
        scan_combo.bind("<<ComboboxSelected>>", self.update_scan_options)

        # Ports
        ttk.Label(options_frame, text="Ports:").grid(row=1, column=0, sticky=tk.W)
        self.ports_entry = ttk.Entry(options_frame, textvariable=self.ports_var, width=20)
        self.ports_entry.grid(row=1, column=1, sticky=tk.W, padx=5)

        # Output format
        ttk.Label(options_frame, text="Output:").grid(row=2, column=0, sticky=tk.W)
        output_formats = ["Normal", "Verbose", "XML", "Grepable"]
        output_combo = ttk.Combobox(options_frame, textvariable=self.output_var, values=output_formats,
                                    state="readonly")
        output_combo.grid(row=2, column=1, sticky=tk.W, padx=5)

        # Buttons
        button_frame = ttk.Frame(main_frame, padding="10")
        button_frame.pack(fill=tk.X, pady=5)

        scan_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        scan_button.pack(side=tk.LEFT, padx=5)

        clear_button = ttk.Button(button_frame, text="Clear Results", command=self.clear_results)
        clear_button.pack(side=tk.LEFT, padx=5)

        # Results section
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True)

        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, width=80, height=20)
        self.results_text.pack(fill=tk.BOTH, expand=True)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X)

    def update_scan_options(self, event=None):
        scan_type = self.scan_type_var.get()

        if scan_type == "Quick Scan":
            self.ports_var.set("1-1000")
        elif scan_type == "Full Scan":
            self.ports_var.set("1-65535")
        elif scan_type == "Ping Scan":
            self.ports_var.set("")
        elif scan_type == "OS Detection":
            self.ports_var.set("1-1000")
        elif scan_type == "Version Detection":
            self.ports_var.set("1-1000")

    def build_nmap_command(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target to scan")
            return None

        scan_type = self.scan_type_var.get()
        ports = self.ports_var.get().strip()
        output_format = self.output_var.get()

        # Base command
        if platform.system() == "Windows":
            command = ["nmap.exe"]
        else:
            command = ["nmap"]

        # Add scan type options
        if scan_type == "Quick Scan":
            command.extend(["-T4", "-F"])
        elif scan_type == "Full Scan":
            command.extend(["-p-", "-T4"])
        elif scan_type == "Ping Scan":
            command.append("-sn")
        elif scan_type == "OS Detection":
            command.extend(["-O"])
        elif scan_type == "Version Detection":
            command.extend(["-sV"])

        # Add ports if specified
        if ports and scan_type != "Ping Scan":
            command.extend(["-p", ports])

        # Add output format
        if output_format == "Verbose":
            command.append("-v")
        elif output_format == "XML":
            command.append("-oX")
            command.append("-")  # Output to stdout
        elif output_format == "Grepable":
            command.append("-oG")
            command.append("-")  # Output to stdout

        # Add target
        command.append(target)

        return command

    def start_scan(self):
        command = self.build_nmap_command()
        if not command:
            return

        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Starting scan with command: {' '.join(command)}\n\n")
        self.status_var.set("Scanning...")

        # Disable buttons during scan
        for widget in self.root.winfo_children():
            if isinstance(widget, ttk.Button):
                widget.config(state=tk.DISABLED)

        # Run scan in a separate thread to keep GUI responsive
        scan_thread = threading.Thread(target=self.run_scan, args=(command,), daemon=True)
        scan_thread.start()

    def run_scan(self, command):
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            # Read output in real-time
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    self.results_text.insert(tk.END, output)
                    self.results_text.see(tk.END)
                    self.root.update_idletasks()

            # Check for errors
            stderr = process.stderr.read()
            if stderr:
                self.results_text.insert(tk.END, f"\nError:\n{stderr}\n")

            return_code = process.poll()
            if return_code == 0:
                self.status_var.set("Scan completed successfully")
            else:
                self.status_var.set(f"Scan completed with return code {return_code}")

        except FileNotFoundError:
            self.results_text.insert(tk.END,
                                     "\nError: Nmap not found. Please ensure Nmap is installed and in your PATH.\n")
            self.status_var.set("Nmap not found")
        except Exception as e:
            self.results_text.insert(tk.END, f"\nError: {str(e)}\n")
            self.status_var.set("Error during scan")
        finally:
            # Re-enable buttons
            self.root.after(0, self.enable_buttons)

    def enable_buttons(self):
        for widget in self.root.winfo_children():
            if isinstance(widget, ttk.Button):
                widget.config(state=tk.NORMAL)

    def clear_results(self):
        self.results_text.delete(1.0, tk.END)
        self.status_var.set("Ready")


def main():
    root = tk.Tk()
    app = NmapGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
