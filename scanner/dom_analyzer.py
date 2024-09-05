from bs4 import BeautifulSoup
import re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

class DOMAnalyzer:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.chrome_options = Options()
        self.chrome_options.add_argument("--headless")
        self.chrome_options.add_argument("--disable-gpu")
        self.chrome_options.add_argument("--no-sandbox")

    def analyze(self, html_content, url):
        static_vulnerabilities = self.analyze_static(html_content)
        dynamic_vulnerabilities = self.analyze_dynamic(url)
        return static_vulnerabilities + dynamic_vulnerabilities

    def analyze_static(self, html_content):
        vulnerabilities = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Check for potentially dangerous patterns
        dangerous_patterns = [
            (r'document\.write\(.*\)', 'document.write'),
            (r'\.innerHTML\s*=', 'innerHTML assignment'),
            (r'eval\(', 'eval'),
            (r'setTimeout\(.*,', 'setTimeout with string argument'),
            (r'setInterval\(.*,', 'setInterval with string argument'),
        ]
        
        for script in soup.find_all('script'):
            script_content = script.string
            if script_content:
                for pattern, vuln_type in dangerous_patterns:
                    if re.search(pattern, script_content):
                        vulnerabilities.append({
                            'type': 'Potential DOM XSS',
                            'subtype': vuln_type,
                            'location': str(script)[:100] + '...'
                        })
        
        return vulnerabilities

    def analyze_dynamic(self, url):
        vulnerabilities = []
        driver = webdriver.Chrome(options=self.chrome_options)
        try:
            driver.get(url)
            # Inject test payload into various DOM sinks
            sinks = [
                'document.URL', 'document.documentURI', 'document.baseURI',
                'location', 'location.href', 'location.search', 'location.hash'
            ]
            for sink in sinks:
                payload = f"<img src=x onerror=alert('XSS in {sink}')>"
                driver.execute_script(f"{sink} = '{payload}';")
                alerts = driver.execute_script("return window.alerts || [];")
                if alerts:
                    vulnerabilities.append({
                        'type': 'DOM XSS',
                        'sink': sink,
                        'payload': payload
                    })
        except Exception as e:
            self.logger.error(f"Error in dynamic DOM analysis: {e}")
        finally:
            driver.quit()
        
        return vulnerabilities

    def check_vulnerability(self, html_content, payload):
        soup = BeautifulSoup(html_content, 'html.parser')
        return payload in str(soup) or any(payload in str(script) for script in soup.find_all('script'))
