import requests
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

logger = logging.getLogger(__name__)

class WebSpider:
    def __init__(self, base_url, max_pages=50):
        self.base_url = base_url
        self.max_pages = max_pages
        self.visited_urls = set()
        self.to_visit = [base_url]
        self.out_of_scope = set()

    def fetch_page(self, url):
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            logging.error(f"Failed to fetch {url}: {e}")
            return None

    def get_links(self, page_content, base_url):
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
        return urlparse(self.base_url).netloc in parsed_url.netloc

    def crawl(self):
        while self.to_visit and len(self.visited_urls) < self.max_pages:
            current_url = self.to_visit.pop(0)
            if current_url in self.visited_urls:
                continue

            logging.info(f"Crawling: {current_url}")
            page_content = self.fetch_page(current_url)
            if not page_content:
                continue

            self.visited_urls.add(current_url)
            links = self.get_links(page_content, current_url)
            for link in links:
                if link not in self.visited_urls and self.is_valid_url(link):
                    if self.is_same_domain(link):
                        self.to_visit.append(link)
                    else:
                        self.out_of_scope.add(link)

        logging.info(f"Crawled {len(self.visited_urls)} pages.")
        return (list(self.visited_urls), list(self.out_of_scope))
