import re
import esprima

class JavaScriptAnalyzer:
    def __init__(self):
        self.dangerous_functions = [
            'eval', 'setTimeout', 'setInterval', 'Function', 'document.write',
            'document.writeln', 'innerHTML', 'outerHTML', 'insertAdjacentHTML'
        ]
        self.dangerous_sinks = [
            'location', 'location.href', 'location.search', 'location.hash',
            'document.URL', 'document.documentURI', 'document.baseURI'
        ]
        self.xss_report_pattern = r'xss-report\?id='
        
    def analyze(self, js_content):
        vulnerabilities = []
        vulnerabilities.extend(self.analyze_dangerous_functions(js_content))
        vulnerabilities.extend(self.analyze_dangerous_sinks(js_content))
        vulnerabilities.extend(self.analyze_dom_xss(js_content))
        vulnerabilities.extend(self.analyze_xss_report(js_content))
        return vulnerabilities

    def analyze_xss_report(self, js_content):
        vulnerabilities = []
        matches = re.finditer(self.xss_report_pattern, js_content)
        for match in matches:
            vulnerabilities.append({
                'type': 'Potential XSS Execution',
                'position': match.start()
            })
        return vulnerabilities

    def analyze_dangerous_functions(self, js_content):
        vulnerabilities = []
        for func in self.dangerous_functions:
            matches = re.finditer(r'\b' + re.escape(func) + r'\s*\(', js_content)
            for match in matches:
                vulnerabilities.append({
                    'type': 'Dangerous Function',
                    'function': func,
                    'position': match.start()
                })
        return vulnerabilities

    def analyze_dangerous_sinks(self, js_content):
        vulnerabilities = []
        for sink in self.dangerous_sinks:
            matches = re.finditer(r'\b' + re.escape(sink) + r'\b', js_content)
            for match in matches:
                vulnerabilities.append({
                    'type': 'Dangerous Sink',
                    'sink': sink,
                    'position': match.start()
                })
        return vulnerabilities

    def analyze_dom_xss(self, js_content):
        vulnerabilities = []
        try:
            ast = esprima.parseScript(js_content)
            self.traverse_ast(ast, vulnerabilities)
        except Exception as e:
            print(f"Error parsing JavaScript: {e}")
        return vulnerabilities

    def traverse_ast(self, node, vulnerabilities):
        if isinstance(node, esprima.nodes.CallExpression):
            if isinstance(node.callee, esprima.nodes.MemberExpression):
                if node.callee.property.name in self.dangerous_functions:
                    vulnerabilities.append({
                        'type': 'Potential DOM XSS',
                        'function': node.callee.property.name,
                        'position': node.range[0]
                    })
        for key, value in node.__dict__.items():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, esprima.nodes.Node):
                        self.traverse_ast(item, vulnerabilities)
            elif isinstance(value, esprima.nodes.Node):
                self.traverse_ast(value, vulnerabilities)
