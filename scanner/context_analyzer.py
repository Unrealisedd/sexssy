import re

class ContextAnalyzer:
    def analyze_form(self, form):
        context = {}
        if 'action' in form.attrs:
            context['action'] = form['action']
        if 'method' in form.attrs:
            context['method'] = form['method'].lower()
        
        input_types = [input.get('type', 'text').lower() for input in form.find_all('input')]
        context['input_types'] = input_types
        
        return context

    def analyze_url_param(self, param, value):
        context = {'param': param}
        if re.search(r'[<>"\'&]', value):
            context['filtered_chars'] = re.findall(r'[<>"\'&]', value)
        return context

    def analyze_header(self, header):
        context = {'header': header}
        if header.lower() in ['user-agent', 'referer']:
            context['encoding'] = 'url'
        return context

    def analyze_response(self, response):
        context = {}
        content_type = response.headers.get('Content-Type', '')
        if 'html' in content_type:
            context['content_type'] = 'html'
        elif 'javascript' in content_type:
            context['content_type'] = 'javascript'
        elif 'json' in content_type:
            context['content_type'] = 'json'
        
        security_headers = {
            'X-XSS-Protection': response.headers.get('X-XSS-Protection'),
            'Content-Security-Policy': response.headers.get('Content-Security-Policy')
        }
        context['security_headers'] = security_headers
        
        return context

    def analyze_path(self, path_part):
        context = {'path_part': path_part}
        if re.search(r'[<>"\'&]', path_part):
            context['filtered_chars'] = re.findall(r'[<>"\'&]', path_part)
        return context
