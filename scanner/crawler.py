import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class Crawler:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config['user_agent']})
        self.visited_urls = set()

    def crawl(self, start_url, max_depth):
        self.visited_urls.clear()
        return self._crawl_recursive(start_url, max_depth)

    def _crawl_recursive(self, url, depth):
        if depth == 0 or url in self.visited_urls:
            return []

        self.visited_urls.add(url)
        self.logger.info(f"Crawling: {url}")

        try:
            response = self.session.get(url, timeout=self.config['timeout'])
            if not response.headers.get('content-type', '').startswith('text/html'):
                return [url]

            soup = BeautifulSoup(response.text, 'html.parser')
            urls = [url]

            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                if self.is_valid_url(full_url):
                    urls.extend(self._crawl_recursive(full_url, depth - 1))

            return list(set(urls))  # Remove duplicates
        except Exception as e:
            self.logger.error(f"Error crawling {url}: {e}")
            return [url]

    def is_valid_url(self, url):
        parsed = urlparse(url)
        return bool(parsed.netloc) and bool(parsed.scheme)
