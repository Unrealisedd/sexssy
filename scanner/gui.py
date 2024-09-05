import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import yaml
from scanner.core import XSSScanner
from scanner.config import load_config
from scanner.utils import setup_logging, generate_report
from scanner.auth_manager import AuthManager
from scanner.waf_detector import WAFDetector
from scanner.plugin_manager import PluginManager
from scanner.crawler import Crawler
from scanner.distributed_scanner import DistributedScanner

class XSSScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Advanced XSS Scanner")
        master.geometry("800x600")
        master.configure(bg='#f0f0f0')

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TButton', font=('Arial', 10), borderwidth=1)
        self.style.configure('TLabel', font=('Arial', 10), background='#f0f0f0')
        self.style.configure('TEntry', font=('Arial', 10))
        self.style.configure('TCheckbutton', font=('Arial', 10), background='#f0f0f0')

        self.notebook = ttk.Notebook(master)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=10)

        self.create_scan_tab()
        self.create_config_tab()
        self.create_results_tab()
        self.create_advanced_tab()

    def create_scan_tab(self):
        scan_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(scan_frame, text="Scan")

        ttk.Label(scan_frame, text="Target URL:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.url_entry = ttk.Entry(scan_frame, width=50)
        self.url_entry.grid(row=0, column=1, padx=5, pady=5, columnspan=2)

        ttk.Label(scan_frame, text="Config File:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.config_entry = ttk.Entry(scan_frame, width=50)
        self.config_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(scan_frame, text="Browse", command=self.browse_config).grid(row=1, column=2, padx=5, pady=5)

        self.crawl_var = tk.BooleanVar()
        ttk.Checkbutton(scan_frame, text="Enable Crawling", variable=self.crawl_var).grid(row=2, column=0, columnspan=3, padx=5, pady=5, sticky="w")

        self.distributed_var = tk.BooleanVar()
        ttk.Checkbutton(scan_frame, text="Enable Distributed Scanning", variable=self.distributed_var).grid(row=3, column=0, columnspan=3, padx=5, pady=5, sticky="w")

        ttk.Button(scan_frame, text="Start Scan", command=self.start_scan, style='TButton').grid(row=4, column=0, columnspan=3, padx=5, pady=20)

        self.progress = ttk.Progressbar(scan_frame, orient="horizontal", length=300, mode="indeterminate")
        self.progress.grid(row=5, column=0, columnspan=3, padx=5, pady=5)

    def create_config_tab(self):
        config_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(config_frame, text="Configuration")

        ttk.Label(config_frame, text="Max Threads:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.max_threads_entry = ttk.Entry(config_frame, width=10)
        self.max_threads_entry.grid(row=0, column=1, padx=5, pady=5)
        self.max_threads_entry.insert(0, "10")

        ttk.Label(config_frame, text="User Agent:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.user_agent_entry = ttk.Entry(config_frame, width=50)
        self.user_agent_entry.grid(row=1, column=1, padx=5, pady=5)
        self.user_agent_entry.insert(0, "XSSScanner/1.0")

        ttk.Label(config_frame, text="Crawl Depth:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.crawl_depth_entry = ttk.Entry(config_frame, width=10)
        self.crawl_depth_entry.grid(row=2, column=1, padx=5, pady=5)
        self.crawl_depth_entry.insert(0, "3")

        ttk.Label(config_frame, text="Custom Payloads:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.custom_payloads_entry = ttk.Entry(config_frame, width=50)
        self.custom_payloads_entry.grid(row=3, column=1, padx=5, pady=5)
        ttk.Button(config_frame, text="Browse", command=self.browse_payloads).grid(row=3, column=2, padx=5, pady=5)

        ttk.Button(config_frame, text="Save Configuration", command=self.save_config, style='TButton').grid(row=4, column=0, columnspan=3, padx=5, pady=20)

    def create_results_tab(self):
        results_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(results_frame, text="Results")

        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, width=90, height=30)
        self.results_text.pack(expand=True, fill="both", padx=5, pady=5)

        ttk.Button(results_frame, text="Save Results", command=self.save_results, style='TButton').pack(pady=10)

    def create_advanced_tab(self):
        advanced_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(advanced_frame, text="Advanced")

        ttk.Label(advanced_frame, text="Authentication Config:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.auth_config_entry = ttk.Entry(advanced_frame, width=50)
        self.auth_config_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(advanced_frame, text="Browse", command=self.browse_auth_config).grid(row=0, column=2, padx=5, pady=5)

        self.waf_detection_var = tk.BooleanVar()
        ttk.Checkbutton(advanced_frame, text="Enable WAF Detection", variable=self.waf_detection_var).grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky="w")

        ttk.Label(advanced_frame, text="Plugin Directory:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.plugin_dir_entry = ttk.Entry(advanced_frame, width=50)
        self.plugin_dir_entry.grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(advanced_frame, text="Browse", command=self.browse_plugin_dir).grid(row=2, column=2, padx=5, pady=5)

    def browse_config(self):
        filename = filedialog.askopenfilename(filetypes=[("YAML files", "*.yaml"), ("All files", "*.*")])
        if filename:
            self.config_entry.delete(0, tk.END)
            self.config_entry.insert(0, filename)

    def browse_payloads(self):
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            self.custom_payloads_entry.delete(0, tk.END)
            self.custom_payloads_entry.insert(0, filename)

    def browse_auth_config(self):
        filename = filedialog.askopenfilename(filetypes=[("YAML files", "*.yaml"), ("All files", "*.*")])
        if filename:
            self.auth_config_entry.delete(0, tk.END)
            self.auth_config_entry.insert(0, filename)

    def browse_plugin_dir(self):
        directory = filedialog.askdirectory()
        if directory:
            self.plugin_dir_entry.delete(0, tk.END)
            self.plugin_dir_entry.insert(0, directory)

    def start_scan(self):
        url = self.url_entry.get()
        config_file = self.config_entry.get()
        
        if not url:
            messagebox.showerror("Error", "Please enter a target URL")
            return

        try:
            config = load_config(config_file)
            config['crawl']['max_depth'] = int(self.crawl_depth_entry.get())
            config['max_threads'] = int(self.max_threads_entry.get())
            config['user_agent'] = self.user_agent_entry.get()

            logger = setup_logging(True)
            auth_manager = AuthManager(config, logger)
            
            if self.auth_config_entry.get():
                auth_manager.load_auth_config(self.auth_config_entry.get())

            waf_detector = WAFDetector(config, logger) if self.waf_detection_var.get() else None
            plugin_manager = PluginManager(config, logger)
            
            if self.plugin_dir_entry.get():
                plugin_manager.load_plugins(self.plugin_dir_entry.get())

            scanner = XSSScanner(config, logger, auth_manager, waf_detector, plugin_manager)
            
            if self.crawl_var.get():
                crawler = Crawler(config, logger, auth_manager)
                urls = crawler.crawl(url, config['crawl']['max_depth'])
            else:
                urls = [url]

            self.progress.start()
            
            if self.distributed_var.get():
                distributed_scanner = DistributedScanner(config, logger)
                results = distributed_scanner.scan(scanner, urls)
            else:
                results = scanner.scan_multiple_urls(urls)

            report = generate_report(results, config)
            
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, report)
            
            self.progress.stop()
            messagebox.showinfo("Scan Complete", "XSS scan completed successfully")
        except Exception as e:
            self.progress.stop()
            messagebox.showerror("Error", f"An error occurred during the scan: {str(e)}")

    def save_config(self):
        config = {
            'max_threads': int(self.max_threads_entry.get()),
            'user_agent': self.user_agent_entry.get(),
            'crawl': {
                'max_depth': int(self.crawl_depth_entry.get())
            },
            'custom_payloads': self.custom_payloads_entry.get(),
            'auth_config': self.auth_config_entry.get(),
            'waf_detection': self.waf_detection_var.get(),
            'plugin_directory': self.plugin_dir_entry.get()
        }
        
        filename = filedialog.asksaveasfilename(defaultextension=".yaml", filetypes=[("YAML files", "*.yaml"), ("All files", "*.*")])
        if filename:
            with open(filename, 'w') as f:
                yaml.dump(config, f)
            messagebox.showinfo("Configuration Saved", f"Configuration saved to {filename}")

    def save_results(self):
        results = self.results_text.get(1.0, tk.END)
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            with open(filename, 'w') as f:
                f.write(results)
            messagebox.showinfo("Results Saved", f"Results saved to {filename}")

# The GUI is launched from xss_scanner.py, so we don't need a main block here