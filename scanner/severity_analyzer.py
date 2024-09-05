class SeverityAnalyzer:
    def __init__(self):
        self.severity_levels = {
            'Critical': 4,
            'High': 3,
            'Medium': 2,
            'Low': 1,
            'Info': 0
        }

    def analyze(self, scan_results):
        for vulnerability in scan_results['vulnerabilities']:
            severity = self._calculate_severity(vulnerability)
            vulnerability['severity'] = severity
            vulnerability['remediation'] = self._get_remediation(vulnerability)

    def _calculate_severity(self, vulnerability):
        vuln_type = vulnerability.get('type', '')
        if 'DOM XSS' in vuln_type:
            return 'High'
        elif 'Reflected XSS' in vuln_type:
            return 'Medium'
        elif 'Stored XSS' in vuln_type:
            return 'Critical'
        else:
            return 'Low'

    def _get_remediation(self, vulnerability):
        vuln_type = vulnerability.get('type', '')
        if 'DOM XSS' in vuln_type:
            return "Sanitize and validate all data used in DOM manipulations. Use safe DOM APIs like innerText instead of innerHTML."
        elif 'Reflected XSS' in vuln_type:
            return "Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers."
        elif 'Stored XSS' in vuln_type:
            return "Implement strict input validation and sanitization. Use HTML encoding when displaying user-supplied data."
        else:
            return "Review the code and implement proper security controls based on the specific vulnerability."
