import requests
import re

class WAFDetector:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.waf_signatures = {
            'Cloudflare': [
                'cf-ray',
                '__cfduid',
                'cf-browser-verification'
            ],
            'AWS WAF': [
                'x-amzn-RequestId',
                'x-amz-cf-id',
                'x-amz-id-2'
            ],
            'ModSecurity': [
                'mod_security',
                'NOYB'
            ],
            'Imperva': [
                'X-Iinfo',
                'visid_incap'
            ]
        }

    def detect(self, url):
        try:
            response = requests.get(url, headers={'User-Agent': self.config['user_agent']})
            headers = response.headers
            content = response.text

            for waf, signatures in self.waf_signatures.items():
                for signature in signatures:
                    if signature.lower() in headers or signature in content:
                        return {'name': waf, 'signature': signature}

            # Check for generic WAF behaviors
            if self._check_generic_waf(response):
                return {'name': 'Unknown WAF', 'signature': 'Generic WAF behavior detected'}

        except Exception as e:
            self.logger.error(f"Error detecting WAF: {e}")

        return None

    def _check_generic_waf(self, response):
        # Check for common WAF response codes
        if response.status_code in [403, 406, 429, 503]:
            return True

        # Check for common WAF keywords in response content
        waf_keywords = ['firewall', 'protection', 'blocked', 'security']
        return any(keyword in response.text.lower() for keyword in waf_keywords)

    def bypass_waf(self, url, payload):
        # Implement WAF bypass techniques
        bypass_techniques = [
            self._encode_payload,
            self._add_noise,
            self._split_payload,
            self._use_alternate_encoding
        ]

        for technique in bypass_techniques:
            modified_payload = technique(payload)
            if self._test_bypass(url, modified_payload):
                return modified_payload

        return payload

    def _encode_payload(self, payload):
        return ''.join(f'%{ord(c):02X}' for c in payload)

    def _add_noise(self, payload):
        return f"{'A' * 100}{payload}{'B' * 100}"

    def _split_payload(self, payload):
        mid = len(payload) // 2
        return f"{payload[:mid]}{'C' * 10}{payload[mid:]}"

    def _use_alternate_encoding(self, payload):
        return payload.encode('utf-16').decode('utf-16')

    def _test_bypass(self, url, payload):
        try:
            response = requests.get(url, params={'test': payload}, headers={'User-Agent': self.config['user_agent']})
            return payload in response.text and response.status_code == 200
        except Exception as e:
            self.logger.error(f"Error testing WAF bypass: {e}")
            return False
