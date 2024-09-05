import logging
import json
from datetime import datetime
from scanner.result_analyzer import ResultAnalyzer

def setup_logging(verbose):
    logger = logging.getLogger('XSSScanner')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    file_handler = logging.FileHandler('xss_scanner.log')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger

def generate_report(results, config):
    analyzer = ResultAnalyzer(results)
    analysis = analyzer.analyze()
    charts = analyzer.generate_charts()

    report = {
        'scan_time': datetime.now().isoformat(),
        'config': sanitize_config(config),
        'results': results,
        'analysis': analysis,
        'charts': charts
    }

    if config['reporting']['output_format'] == 'json':
        return json.dumps(report, indent=2)
    elif config['reporting']['output_format'] == 'html':
        return generate_html_report(report)
    else:
        return str(report)

def generate_html_report(report):
    html = f"""
    <html>
    <head>
        <title>XSS Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; }}
            .chart {{ max-width: 600px; margin: 20px auto; }}
        </style>
    </head>
    <body>
        <h1>XSS Scan Report</h1>
        <p>Scan Time: {report['scan_time']}</p>
        <h2>Analysis</h2>
        <ul>
            <li>Total URLs Scanned: {report['analysis']['total_urls']}</li>
            <li>Total Vulnerabilities: {report['analysis']['total_vulnerabilities']}</li>
        </ul>
        <h3>Vulnerability Types Distribution</h3>
        <img class="chart" src="data:image/png;base64,{report['charts']['vulnerability_types']}" alt="Vulnerability Types Chart">
        <h3>Severity Distribution</h3>
        <img class="chart" src="data:image/png;base64,{report['charts']['severity_distribution']}" alt="Severity Distribution Chart">
        <h3>Most Vulnerable URLs</h3>
        <ol>
            {''.join(f'<li>{url}: {count} vulnerabilities</li>' for url, count in report['analysis']['most_vulnerable_urls'])}
        </ol>
        <h3>WAF Presence</h3>
        <p>{report['analysis']['waf_presence']['percentage']:.2f}% of scanned URLs have WAF protection</p>
        <h2>Detailed Results</h2>
        {''.join(generate_url_result_html(result) for result in report['results'])}
    </body>
    </html>
    """
    return html

def generate_url_result_html(result):
    return f"""
    <h3>{result['url']}</h3>
    <ul>
        {''.join(f'<li>{vuln["type"]} (Severity: {vuln["severity"]}): {vuln.get("description", "")}</li>' for vuln in result['vulnerabilities'])}
    </ul>
    """

def sanitize_config(config):
    # Remove sensitive information from config before including in report
    sanitized = config.copy()
    if 'redis' in sanitized:
        sanitized['redis']['password'] = '********'
    return sanitized
