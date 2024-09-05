import argparse
import sys
from scanner.core import XSSScanner
from scanner.utils import setup_logging, generate_report
from scanner.config import load_config
from scanner.crawler import Crawler
from scanner.auth_manager import AuthManager
from scanner.waf_detector import WAFDetector
from scanner.plugin_manager import PluginManager
from scanner.distributed_scanner import DistributedScanner

def main():
    parser = argparse.ArgumentParser(description="Advanced XSS Vulnerability Scanner")
    parser.add_argument("-u", "--url", help="Target URL to test for XSS")
    parser.add_argument("-f", "--file", help="File containing list of URLs to test")
    parser.add_argument("-c", "--config", help="Configuration file path", default="config.yaml")
    parser.add_argument("-o", "--output", help="Output file for the report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--crawl", action="store_true", help="Enable web crawling")
    parser.add_argument("--depth", type=int, default=3, help="Crawling depth")
    parser.add_argument("--custom-payloads", help="File containing custom XSS payloads")
    parser.add_argument("--auth", help="Authentication configuration file")
    parser.add_argument("--distributed", action="store_true", help="Enable distributed scanning")
    parser.add_argument("--gui", action="store_true", help="Launch GUI interface")
    args = parser.parse_args()

    if args.gui:
        launch_gui()
        return

    if not args.url and not args.file:
        parser.error("Either a URL (-u) or a file with URLs (-f) must be provided.")

    config = load_config(args.config)
    logger = setup_logging(args.verbose)

    if args.custom_payloads:
        with open(args.custom_payloads, 'r') as f:
            custom_payloads = [line.strip() for line in f]
        config['payloads']['custom'] = custom_payloads

    auth_manager = AuthManager(config, logger)
    if args.auth:
        auth_manager.load_auth_config(args.auth)

    waf_detector = WAFDetector(config, logger)
    plugin_manager = PluginManager(config, logger)

    scanner = XSSScanner(config, logger, auth_manager, waf_detector, plugin_manager)

    if args.crawl:
        crawler = Crawler(config, logger, auth_manager)
        urls = crawler.crawl(args.url, args.depth)
    elif args.url:
        urls = [args.url]
    elif args.file:
        with open(args.file, 'r') as f:
            urls = [line.strip() for line in f]

    if args.distributed:
        distributed_scanner = DistributedScanner(config, logger)
        results = distributed_scanner.scan(scanner, urls)
    else:
        results = scanner.scan_multiple_urls(urls)

    report = generate_report(results, config)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report saved to {args.output}")
    else:
        print(report)

def launch_gui():
    try:
        import tkinter as tk
        from scanner.gui import XSSScannerGUI
        root = tk.Tk()
        app = XSSScannerGUI(root)
        root.mainloop()
    except ImportError:
        print("GUI dependencies not installed. Please install tkinter to use the GUI.")
        sys.exit(1)

if __name__ == "__main__":
    main()
