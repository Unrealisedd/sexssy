import random
import html
import urllib.parse
import json
import uuid
import base64

class PayloadGenerator:
    def __init__(self, payload_config):
        self.basic_payloads = self.load_payloads(payload_config['basic']['file'])
        self.advanced_payloads = self.load_payloads(payload_config['advanced']['file'])
        self.evasion_techniques = payload_config['evasion']
        self.custom_payloads = payload_config.get('custom', [])

    def load_payloads(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        except IOError as e:
            raise ValueError(f"Unable to read file {file_path}: {str(e)}")

    def generate_payloads(self, context):
        payloads = self.basic_payloads + self.advanced_payloads + self.custom_payloads
        
        # Generate a unique identifier for this scan
        scan_id = str(uuid.uuid4())

        # Wrap each payload with execution-reporting code
        payloads = [self.wrap_payload(p, scan_id) for p in payloads]
        
        if context.get('filtered_chars'):
            payloads = [p for p in payloads if not any(char.encode() in p for char in context['filtered_chars'])]
        
        if context.get('encoding') == 'url':
            payloads = [self.url_encode(p) for p in payloads]
        elif context.get('encoding') == 'html':
            payloads = [self.html_encode(p) for p in payloads]
        
        if context.get('tag'):
            payloads = [b"".join([context['tag'].encode(), b"=", p]) for p in payloads]
        
        evasion_payloads = [self.apply_evasion(p) for p in payloads]
        payloads.extend(evasion_payloads)
        
        if context.get('content_type') == 'json':
            payloads = [self.json_encode(p) for p in payloads]
        
        return list(set(payloads))  # Remove duplicates

    def wrap_payload(self, payload, scan_id):
        # Encode the payload and scan_id
        encoded_payload = base64.b64encode(payload).decode()
        # Wrap the payload with code that will report back when executed
        wrapped = f"""
        <script>
        (function() {{
            var data = {{
                id: '{scan_id}',
                payload: '{encoded_payload}',
                url: window.location.href
            }};
            var event = new CustomEvent('xssDetected', {{ detail: data }});
            document.dispatchEvent(event);
        }})();
        </script>
        """.encode()
        return wrapped
        
    def apply_evasion(self, payload):
        technique = random.choice(self.evasion_techniques)
        if technique == 'case_swapping':
            return bytes(c ^ 0x20 if 65 <= c <= 90 or 97 <= c <= 122 else c for c in payload)
        elif technique == 'null_bytes':
            return b'\0'.join([payload[i:i+1] for i in range(len(payload))])
        elif technique == 'encoding':
            return b''.join([b'\\x%02x' % c for c in payload])
        elif technique == 'double_encoding':
            return self.url_encode(self.url_encode(payload))
        return payload

    @staticmethod
    def url_encode(payload):
        return urllib.parse.quote_from_bytes(payload).encode()

    @staticmethod
    def html_encode(payload):
        return html.escape(payload.decode(errors='ignore')).encode()

    @staticmethod
    def json_encode(payload):
        return json.dumps(payload.decode(errors='ignore'))[1:-1].encode()  # Remove surrounding quotes

    def generate_mutation(self, payload):
        mutations = [
            lambda p: p.replace(b'<', b'<%00'),
            lambda p: p.replace(b'"', b'\\"'),
            lambda p: p.replace(b"'", b"\\'"),
            lambda p: p.replace(b' ', b'+'),
            lambda p: bytes(c ^ 0x20 if random.random() > 0.7 and (65 <= c <= 90 or 97 <= c <= 122) else c for c in p),
        ]
        return random.choice(mutations)(payload)
