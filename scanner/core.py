import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import concurrent.futures
from .payload_generator import PayloadGenerator
from .dom_analyzer import DOMAnalyzer
from .context_analyzer import ContextAnalyzer
from .javascript_analyzer import JavaScriptAnalyzer
from .severity_analyzer import SeverityAnalyzer
import hashlib
import secrets
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException
from webdriver_manager.chrome import ChromeDriverManager
import json
import base64
import time
import urllib.parse
import os
import subprocess

class XSSScanner:
    def __init__(self, config, logger, auth_manager, waf_detector, plugin_manager):
        self.config = config
        self.logger = logger
        self.session = requests.Session()
        self.driver = None
        self.session.headers.update({'User-Agent': config['user_agent']})
        self.payload_generator = PayloadGenerator(config['payloads'])
        self.dom_analyzer = DOMAnalyzer(config, logger)
        self.context_analyzer = ContextAnalyzer()
        self.js_analyzer = JavaScriptAnalyzer()
        self.severity_analyzer = SeverityAnalyzer()
        self.auth_manager = auth_manager
        self.waf_detector = waf_detector
        self.plugin_manager = plugin_manager
        self.session_id = self.generate_session_id()
        self.chrome_options = Options()
        if config['browser']['headless']:
            self.chrome_options.add_argument("--headless")
        if config['browser']['no_sandbox']:
            self.chrome_options.add_argument("--no-sandbox")
        if config['browser']['disable_dev_shm_usage']:
            self.chrome_options.add_argument("--disable-dev-shm-usage")
            
        self.report_file = config['reporting']['local_report_file']
        self.discord_webhook_url = config['reporting']['discord_webhook_url']
    
    def initialize_browser(self):
        if self.driver is None:
            chrome_service = Service(ChromeDriverManager().install())
            chrome_service.creation_flags = subprocess.CREATE_NO_WINDOW
            self.driver = webdriver.Chrome(service=chrome_service, options=self.chrome_options)
            
    def close_browser(self):
        if self.driver:
            self.driver.quit()
            self.driver = None

    def generate_session_id(self):
        return hashlib.sha256(secrets.token_bytes(32)).hexdigest()

    def scan_multiple_urls(self, urls):
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['max_threads']) as executor:
            future_to_url = {executor.submit(self.scan_url, url): url for url in urls}
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    results.append(future.result())
                except Exception as exc:
                    self.logger.error(f"An error occurred while scanning {url}: {exc}")
                    results.append({'url': url, 'error': str(exc)})
        return results

    
    def scan_url(self, url):
        self.logger.info(f"Scanning URL: {url}")
    
        scan_results = {
            'url': url,
            'vulnerabilities': [],
            'waf_info': None,
            'additional_scans': {}
        }
        try:
            self.logger.debug("Detecting WAF...")
            scan_results['waf_info'] = self.waf_detector.detect(url) if self.waf_detector else None
            self.logger.debug(f"WAF detection result: {scan_results['waf_info']}")
            self.logger.debug("Generating payloads...")
            payloads = self.payload_generator.generate_payloads({})
            self.logger.debug(f"Generated {len(payloads)} payloads")

            # Limit payloads for testing
            max_payloads = 100  # Adjust this number as needed
            payloads = payloads[:max_payloads]
            self.logger.debug(f"Testing {len(payloads)} payloads")

            self.initialize_browser()
            try:
                for i, payload in enumerate(payloads, 1):
                    self.logger.debug(f"Testing payload {i}/{len(payloads)}: {payload[:50]}...")  # Log first 50 chars of payload
                    start_time = time.time()
                    result = self.test_single_payload(url, payload)
                    end_time = time.time()
                    self.logger.debug(f"Payload test completed in {end_time - start_time:.2f} seconds")
                    if result:
                        scan_results['vulnerabilities'].append(result)
                        self.logger.info(f"Vulnerability found with payload: {payload}")
            finally:
                self.close_browser()

            self.logger.debug("Basic scan completed. Performing additional scans...")
            additional_results = self.perform_additional_scans(url)
            scan_results['additional_scans'] = additional_results
            self.logger.debug("Additional scans completed")

            # Run plugins
            plugin_results = self.plugin_manager.run_plugins(url, self.session)
            scan_results['plugin_results'] = plugin_results

            # Analyze severity
            self.severity_analyzer.analyze(scan_results)
        except Exception as e:
            self.logger.error(f"Error during scan of {url}: {str(e)}", exc_info=True)
            scan_results['error'] = str(e)
        return scan_results

    def perform_additional_scans(self, url):
        additional_results = {}
        try:
            additional_results['forms'] = self.scan_forms(url)
            additional_results['url_params'] = self.scan_url_params(url)
            additional_results['headers'] = self.scan_headers(url)
            additional_results['dom'] = self.scan_dom(url)
            additional_results['javascript'] = self.scan_javascript(url)
            additional_results['path'] = self.scan_path_injection(url)
            additional_results['post'] = self.scan_post_injection(url)
            additional_results['get'] = self.scan_get_injection(url)
        except Exception as e:
            self.logger.error(f"Error during additional scans: {str(e)}", exc_info=True)
            additional_results['error'] = str(e)
        return additional_results


    def test_payload(self, url, payloads):
        self.initialize_browser()
        results = []

        try:
            for payload in payloads:
                result = self.test_single_payload(url, payload)
                if result:
                    results.append(result)
        finally:
            self.close_browser()

        return results

    
    def test_single_payload(self, url, payload):
        try:
            # Convert payload to string if it's not already
            payload_bytes = payload if isinstance(payload, bytes) else str(payload).encode()
            # Set up a listener for XSS reports
            self.driver.execute_script("""
    window.xssDetected = false;
    document.addEventListener('xssDetected', function(e) {
        window.xssDetected = true;
        window.xssData = e.detail;
    }, {once: true});
            """)
            # Navigate to the URL with the payload
            full_url = f"{url}?input={urllib.parse.quote(payload.decode())}"
            self.driver.get(full_url)
            # Wait for XSS detection or timeout after a short period (e.g., 5 seconds)
            try:
                WebDriverWait(self.driver, 5).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
            except TimeoutException:
                self.logger.warning(f"Timeout waiting for page load with payload: {payload[:50]}...")
                return None

            # Check if XSS was detected
            xss_detected = self.driver.execute_script("return window.xssDetected;")
            if xss_detected:
                xss_data = self.driver.execute_script("return window.xssData;")
                decoded_payload = base64.b64decode(xss_data['payload']).decode(errors='ignore')
                self.report_xss(xss_data['url'], decoded_payload)
                return {
                    'type': 'Executed XSS',
                    'severity': 'Critical',
                    'description': f'Found an executed XSS vulnerability with payload: {decoded_payload}',
                    'payload': decoded_payload,
                    'url': xss_data['url']
                }
        except Exception as e:
            self.logger.error(f"Error testing payload {payload.decode(errors='ignore')} on {url}: {str(e)}")
        return None
        
    def report_xss(self, url, payload):
        # Append to local HTML file
        with open(self.report_file, 'a') as f:
            f.write(f"<p>XSS detected on {url} with payload: {payload}</p>\n")

        # Send to Discord webhook if configured
        if self.discord_webhook_url:
            data = {
                "content": f"XSS detected on {url} with payload: {payload}"
            }
            try:
                request.post(self.discord_webhook_url, json=data)
            except Exception as e:
                self.logger.error(f"Error sending to discord webhook: {str(e)}")
            
    def scan_forms(self, url):
        forms = self.get_all_forms(url)
        vulnerable_forms = []
        for form in forms:
            form_details = self.get_form_details(form)
            context = self.context_analyzer.analyze_form(form)
            payloads = self.payload_generator.generate_payloads(context)
            for payload in payloads:
                if self.test_xss_in_form(form_details, url, payload):
                    vulnerable_forms.append({
                        'form': form_details,
                        'payload': payload
                    })
                    break
        return vulnerable_forms

    def scan_url_params(self, url):
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        vulnerable_params = []
        for param, values in query_params.items():
            context = self.context_analyzer.analyze_url_param(param, values[0])
            payloads = self.payload_generator.generate_payloads(context)
            for payload in payloads:
                if self.test_xss_in_url_param(url, param, payload):
                    vulnerable_params.append({
                        'param': param,
                        'payload': payload
                    })
                    break
        return vulnerable_params

    def scan_headers(self, url):
        vulnerable_headers = []
        headers_to_test = ['User-Agent', 'Referer', 'X-Forwarded-For', 'Cookie']
        for header in headers_to_test:
            context = self.context_analyzer.analyze_header(header)
            payloads = self.payload_generator.generate_payloads(context)
            for payload in payloads:
                if self.test_xss_in_header(url, header, payload):
                    vulnerable_headers.append({
                        'header': header,
                        'payload': payload
                    })
                    break
        return vulnerable_headers

    def scan_dom(self, url):
        response = self.session.get(url)
        dom_xss = self.dom_analyzer.analyze(response.text)
        return dom_xss

    def scan_javascript(self, url):
        response = self.session.get(url)
        js_vulnerabilities = self.js_analyzer.analyze(response.text)
        return js_vulnerabilities

    def scan_path_injection(self, url):
        parsed_url = urlparse(url)
        path_parts = parsed_url.path.split('/')
        vulnerable_paths = []
        for i, part in enumerate(path_parts):
            if part:
                context = self.context_analyzer.analyze_path(part)
                payloads = self.payload_generator.generate_payloads(context)
                for payload in payloads:
                    new_path_parts = path_parts.copy()
                    new_path_parts[i] = payload
                    new_url = parsed_url._replace(path='/'.join(new_path_parts)).geturl()
                    if self.test_xss_in_path(new_url):
                        vulnerable_paths.append({
                            'path_part': part,
                            'payload': payload
                        })
                        break
        return vulnerable_paths

    def scan_post_injection(self, url):
        forms = self.get_all_forms(url)
        vulnerable_posts = []
        for form in forms:
            if form.get('method', '').lower() == 'post':
                form_details = self.get_form_details(form)
                context = self.context_analyzer.analyze_form(form)
                payloads = self.payload_generator.generate_payloads(context)
                for payload in payloads:
                    if self.test_xss_in_post(form_details, url, payload):
                        vulnerable_posts.append({
                            'form': form_details,
                            'payload': payload
                        })
                        break
        return vulnerable_posts

    def scan_get_injection(self, url):
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        vulnerable_gets = []
        for param, values in query_params.items():
            context = self.context_analyzer.analyze_url_param(param, values[0])
            payloads = self.payload_generator.generate_payloads(context)
            for payload in payloads:
                if self.test_xss_in_get(url, param, payload):
                    vulnerable_gets.append({
                        'param': param,
                        'payload': payload
                    })
                    break
        return vulnerable_gets

    def get_all_forms(self, url):
        response = self.session.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup.find_all("form")

    def get_form_details(self, form):
        details = {}
        action = form.attrs.get("action", "").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            inputs.append({"type": input_type, "name": input_name, "value": input_value})
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def test_xss_in_form(self, form_details, url, payload):
        target_url = urljoin(url, form_details["action"])
        data = {}
        for input_tag in form_details["inputs"]:
            if input_tag["type"] == "text" or input_tag["type"] == "search":
                data[input_tag["name"]] = payload
            elif input_tag["type"] != "submit":
                data[input_tag["name"]] = input_tag["value"]
        if form_details["method"] == "post":
            res = self.session.post(target_url, data=data)
        elif form_details["method"] == "get":
            res = self.session.get(target_url, params=data)
        
        return self.is_vulnerable(res, payload)

    def test_xss_in_url_param(self, url, param, payload):
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        query_params[param] = [payload]
        new_query = '&'.join(f"{k}={v[0]}" for k, v in query_params.items())
        new_url = parsed_url._replace(query=new_query).geturl()
        res = self.session.get(new_url)
        return self.is_vulnerable(res, payload)

    def test_xss_in_header(self, url, header, payload):
        headers = {header: payload}
        res = self.session.get(url, headers=headers)
        return self.is_vulnerable(res, payload)

    def test_xss_in_path(self, url):
        res = self.session.get(url)
        return self.is_vulnerable(res, url)

    def test_xss_in_post(self, form_details, url, payload):
        target_url = urljoin(url, form_details["action"])
        data = {input_tag["name"]: payload if input_tag["type"] in ["text", "search"] else input_tag["value"]
                for input_tag in form_details["inputs"] if input_tag["type"] != "submit"}
        res = self.session.post(target_url, data=data)
        return self.is_vulnerable(res, payload)

    def test_xss_in_get(self, url, param, payload):
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        query_params[param] = [payload]
        new_query = '&'.join(f"{k}={v[0]}" for k, v in query_params.items())
        new_url = parsed_url._replace(query=new_query).geturl()
        res = self.session.get(new_url)
        return self.is_vulnerable(res, payload)

    def is_vulnerable(self, response, payload):
        content_type = response.headers.get('Content-Type', '')
        if 'text/html' in content_type:
            return self.dom_analyzer.check_vulnerability(response.text, payload)
        elif 'application/json' in content_type:
            return payload in response.text
        elif 'text/javascript' in content_type:
            return self.js_analyzer.check_vulnerability(response.text, payload)
        return False
