from collections import Counter
import json
import matplotlib.pyplot as plt
from io import BytesIO
import base64

class ResultAnalyzer:
    def __init__(self, results):
        self.results = results if isinstance(results, list) else [results]

    def analyze(self):
        if not self.results:
            return {
                'total_urls': 0,
                'total_vulnerabilities': 0,
                'vulnerability_types': {},
                'severity_distribution': {},
                'most_vulnerable_urls': [],
                'waf_presence': {'total': 0, 'percentage': 0},
            }

        analysis = {
            'total_urls': len(self.results),
            'total_vulnerabilities': sum(len(r.get('vulnerabilities', [])) for r in self.results),
            'vulnerability_types': self.count_vulnerability_types(),
            'severity_distribution': self.analyze_severity(),
            'most_vulnerable_urls': self.find_most_vulnerable_urls(5),
            'waf_presence': self.analyze_waf_presence(),
        }
        return analysis

    def count_vulnerability_types(self):
        vuln_types = [v['type'] for r in self.results for v in r.get('vulnerabilities', [])]
        return dict(Counter(vuln_types))

    def analyze_severity(self):
        severities = [v['severity'] for r in self.results for v in r.get('vulnerabilities', [])]
        return dict(Counter(severities))

    def find_most_vulnerable_urls(self, n):
        url_vuln_count = [(r['url'], len(r.get('vulnerabilities', []))) for r in self.results]
        return sorted(url_vuln_count, key=lambda x: x[1], reverse=True)[:n]

    def analyze_waf_presence(self):
        waf_count = sum(1 for r in self.results if r.get('waf_info'))
        total_results = len(self.results)
        return {
            'total': waf_count,
            'percentage': (waf_count / total_results) * 100 if total_results > 0 else 0
        }

    def generate_charts(self):
        charts = {}
        
        # Vulnerability Types Chart
        plt.figure(figsize=(10, 6))
        vuln_types = self.count_vulnerability_types()
        plt.bar(vuln_types.keys(), vuln_types.values())
        plt.title('Vulnerability Types Distribution')
        plt.xlabel('Vulnerability Type')
        plt.ylabel('Count')
        plt.xticks(rotation=45, ha='right')
        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        charts['vulnerability_types'] = base64.b64encode(buffer.getvalue()).decode()
        plt.close()

        # Severity Distribution Chart
        plt.figure(figsize=(8, 8))
        severity_dist = self.analyze_severity()
        plt.pie(severity_dist.values(), labels=severity_dist.keys(), autopct='%1.1f%%')
        plt.title('Severity Distribution')
        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        charts['severity_distribution'] = base64.b64encode(buffer.getvalue()).decode()
        plt.close()

        return charts