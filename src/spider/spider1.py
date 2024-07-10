import requests
import time
import logging
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

class WebSpider:
    def __init__(self, base_url, login_url=None, login_payload=None, max_pages=100, delay=1, retries=3, output_file="crawled_data.json", respect_robots_txt=True):
        self.base_url = base_url
        self.login_url = login_url
        self.login_payload = login_payload
        self.max_pages = max_pages
        self.visited_urls = set()
        self.to_visit = [base_url]
        self.out_of_scope = set()
        self.delay = delay
        self.retries = retries
        self.output_file = output_file
        self.respect_robots_txt = respect_robots_txt
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'MyWebSpider/1.0 (+http://example.com)'})
        self.robots_txt = None
        self.disallowed_paths = []

    def login(self):
        if self.login_url and self.login_payload:
            try:
                response = self.session.post(self.login_url, data=self.login_payload)
                response.raise_for_status()
                logger.info("Logged in successfully.")
            except requests.RequestException as e:
                logger.error(f"Login failed: {e}")
                raise

    def fetch_page(self, url):
        for attempt in range(self.retries):
            try:
                response = self.session.get(url)
                response.raise_for_status()
                return response.text
            except requests.RequestException as e:
                logger.error(f"Failed to fetch {url} on attempt {attempt + 1}: {e}")
            time.sleep(self.delay)
        return None

    def extract_links(self, page_content, base_url):
        soup = BeautifulSoup(page_content, 'html.parser')
        links = set()

        for tag in soup.find_all(['a', 'link', 'area', 'base'], href=True):
            href = tag.get('href')
            full_url = urljoin(base_url, href)
            parsed_url = urlparse(full_url)
            normalized_url = parsed_url._replace(fragment='').geturl()
            links.add(normalized_url)

        for tag in soup.find_all(['applet', 'audio', 'embed', 'frame', 'iframe', 'input', 'script', 'img', 'video'], src=True):
            src = tag.get('src')
            full_url = urljoin(base_url, src)
            parsed_url = urlparse(full_url)
            normalized_url = parsed_url._replace(fragment='').geturl()
            links.add(normalized_url)

        for tag in soup.find_all('blockquote', cite=True):
            cite = tag.get('cite')
            full_url = urljoin(base_url, cite)
            parsed_url = urlparse(full_url)
            normalized_url = parsed_url._replace(fragment='').geturl()
            links.add(normalized_url)

        for tag in soup.find_all('meta', {'http-equiv': ['location', 'refresh', 'Content-Security-Policy'], 'name': 'msapplication-config'}):
            content = tag.get('content')
            if content:
                full_url = urljoin(base_url, content)
                parsed_url = urlparse(full_url)
                normalized_url = parsed_url._replace(fragment='').geturl()
                links.add(normalized_url)

        return links

    def is_valid_url(self, url):
        parsed_url = urlparse(url)
        return bool(parsed_url.scheme) and bool(parsed_url.netloc)

    def is_same_domain(self, url):
        parsed_url = urlparse(url)
        return urlparse(self.base_url).netloc == parsed_url.netloc

    def read_robots_txt(self):
        robots_url = urljoin(self.base_url, "/robots.txt")
        try:
            response = self.session.get(robots_url)
            if response.status_code == 200:
                self.robots_txt = response.text
                self.parse_robots_txt()
            else:
                logger.info("No robots.txt found or inaccessible.")
        except requests.RequestException as e:
            logger.error(f"Failed to fetch robots.txt: {e}")

    def parse_robots_txt(self):
        if self.robots_txt:
            for line in self.robots_txt.split("\n"):
                if line.strip().startswith("Disallow"):
                    path = line.split(":")[1].strip()
                    self.disallowed_paths.append(path)

    def is_allowed_by_robots(self, url):
        if not self.robots_txt:
            return True
        parsed_url = urlparse(url)
        path = parsed_url.path
        for disallowed_path in self.disallowed_paths:
            if path.startswith(disallowed_path):
                return False
        return True

    def crawl(self):
        if self.login_url and self.login_payload:
            self.login()
        if self.respect_robots_txt:
            self.read_robots_txt()
        while self.to_visit and len(self.visited_urls) < self.max_pages:
            current_url = self.to_visit.pop(0)
            if current_url in self.visited_urls or (self.respect_robots_txt and not self.is_allowed_by_robots(current_url)):
                continue

            logger.info(f"Crawling: {current_url}")
            page_content = self.fetch_page(current_url)
            if not page_content:
                continue

            self.visited_urls.add(current_url)
            links = self.extract_links(page_content, current_url)
            for link in links:
                if link not in self.visited_urls and self.is_valid_url(link):
                    if self.is_same_domain(link):
                        self.to_visit.append(link)
                    else:
                        self.out_of_scope.add(link)

        logger.info(f"Crawled {len(self.visited_urls)} pages.")
        self.save_to_file()

    def save_to_file(self):
        data = {
            'visited_urls': list(self.visited_urls),
            'out_of_scope_urls': list(self.out_of_scope)
        }
        with open(self.output_file, 'w') as f:
            json.dump(data, f, indent=4)
        logger.info(f"Saved crawled data to {self.output_file}")

def main():
    logging.basicConfig(level=logging.INFO)
    start_url = 'https://testportal.helium.sh/'
    login_url = 'http://example.com/login'
    login_payload = {
        'username': 'your_username',
        'password': 'your_password'
    }
    spider = WebSpider(start_url, respect_robots_txt=False)  # Set to False to ignore robots.txt
    spider.crawl()
    print(f"Visited URLs: {spider.visited_urls}")
    print(f"Out of Scope URLs: {spider.out_of_scope}")

if __name__ == '__main__':
    main()
