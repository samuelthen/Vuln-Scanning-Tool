import requests
import time
import logging
import json
import concurrent.futures
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh = logging.FileHandler('web_spider.log')
fh.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)
logger.addHandler(fh)
logger.addHandler(ch)

class EnhancedWebSpider:
    def __init__(self, base_url, login_url=None, login_payload=None, max_pages=10, delay=1, retries=3,
                 output_file="crawled_data.json", respect_robots_txt=True, max_depth=0, max_threads=5,
                 max_duration=0, max_children=0, max_parse_size=0, domains_in_scope=None,
                 query_param_handling=2, send_referer=False, accept_cookies=True, process_forms=True,
                 post_forms=False, parse_html_comments=False, parse_robots_txt=True,
                 parse_sitemap_xml=False, parse_svn_metadata=False, parse_git_metadata=False,
                 parse_ds_store_files=False, handle_odata_params=False, irrelevant_params=None):
        
        self.base_url = base_url
        self.login_url = login_url
        self.login_payload = login_payload
        self.max_pages = max_pages
        self.delay = delay
        self.retries = retries
        self.output_file = output_file
        self.respect_robots_txt = respect_robots_txt
        
        self.max_depth = max_depth
        self.max_threads = max_threads
        self.max_duration = max_duration
        self.max_children = max_children
        self.max_parse_size = max_parse_size
        self.domains_in_scope = domains_in_scope or []
        self.query_param_handling = query_param_handling
        self.send_referer = send_referer
        self.accept_cookies = accept_cookies
        self.process_forms = process_forms
        self.post_forms = post_forms
        self.parse_html_comments = parse_html_comments
        self.parse_robots_txt = parse_robots_txt
        self.parse_sitemap_xml = parse_sitemap_xml
        self.parse_svn_metadata = parse_svn_metadata
        self.parse_git_metadata = parse_git_metadata
        self.parse_ds_store_files = parse_ds_store_files
        self.handle_odata_params = handle_odata_params
        self.irrelevant_params = irrelevant_params or []
        
        self.visited_urls = set()
        self.to_visit = [(base_url, 0)]  # (url, depth)
        self.out_of_scope = set()
        self.session = requests.Session() if self.accept_cookies else None
        self.session.headers.update({'User-Agent': 'EnhancedWebSpider/1.0 (+http://example.com)'})
        self.robots_txt = None
        self.disallowed_paths = []
        self.start_time = None

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
        headers = {'Referer': url} if self.send_referer else {}
        for attempt in range(self.retries):
            try:
                response = self.session.get(url, headers=headers) if self.session else requests.get(url, headers=headers)
                response.raise_for_status()
                return response.text, response.content
            except requests.RequestException as e:
                logger.error(f"Failed to fetch {url} on attempt {attempt + 1}: {e}")
            time.sleep(self.delay)
        return None, None

    def extract_links(self, page_content, base_url):
        soup = BeautifulSoup(page_content, 'html.parser')
        links = set()

        for tag in soup.find_all(['a', 'link', 'area', 'base'], href=True):
            href = tag.get('href')
            full_url = urljoin(base_url, href)
            links.add(self.normalize_url(full_url))

        for tag in soup.find_all(['applet', 'audio', 'embed', 'frame', 'iframe', 'input', 'script', 'img', 'video'], src=True):
            src = tag.get('src')
            full_url = urljoin(base_url, src)
            links.add(self.normalize_url(full_url))

        for tag in soup.find_all('blockquote', cite=True):
            cite = tag.get('cite')
            full_url = urljoin(base_url, cite)
            links.add(self.normalize_url(full_url))

        for tag in soup.find_all('meta', {'http-equiv': ['location', 'refresh', 'Content-Security-Policy'], 'name': 'msapplication-config'}):
            content = tag.get('content')
            if content:
                full_url = urljoin(base_url, content)
                links.add(self.normalize_url(full_url))

        if self.parse_html_comments:
            comments = soup.find_all(string=lambda text: isinstance(text, BeautifulSoup.Comment))
            for comment in comments:
                links.update(self.extract_links_from_text(comment, base_url))

        if self.parse_svn_metadata:
            links.update(self.extract_links_from_text('.svn', base_url))

        if self.parse_git_metadata:
            links.update(self.extract_links_from_text('.git', base_url))

        if self.parse_ds_store_files:
            links.update(self.extract_links_from_text('.DS_Store', base_url))

        return links

    def extract_links_from_text(self, text, base_url):
        links = set()
        for match in re.findall(r'(https?://\S+)', text):
            full_url = urljoin(base_url, match)
            links.add(self.normalize_url(full_url))
        return links

    def normalize_url(self, url):
        parsed_url = urlparse(url)
        return parsed_url._replace(fragment='').geturl()

    def is_valid_url(self, url):
        parsed_url = urlparse(url)
        return bool(parsed_url.scheme) and bool(parsed_url.netloc)

    def is_same_domain(self, url):
        return urlparse(self.base_url).netloc == urlparse(url).netloc

    def read_robots_txt(self):
        robots_url = urljoin(self.base_url, "/robots.txt")
        try:
            response = self.session.get(robots_url) if self.session else requests.get(robots_url)
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

    def should_visit(self, url):
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        if self.query_param_handling == 0:
            url = url.split('?')[0]
        elif self.query_param_handling == 1:
            url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?" + '&'.join(params.keys())
        elif self.handle_odata_params:
            url = self.handle_odata_url(url, params)
        
        return (
            url not in self.visited_urls and
            self.is_valid_url(url) and
            self.is_same_domain(url) and
            (not self.respect_robots_txt or self.is_allowed_by_robots(url)) and
            (not self.domains_in_scope or any(re.match(domain, url) for domain in self.domains_in_scope))
        )

    def handle_odata_url(self, url, params):
        for param in self.irrelevant_params:
            if param in params:
                params.pop(param)
        return f"{url.split('?')[0]}?" + '&'.join(f"{key}={value[0]}" for key, value in params.items())

    def crawl(self):
        if self.login_url and self.login_payload:
            self.login()
        if self.respect_robots_txt:
            self.read_robots_txt()
        
        self.start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.process_url, url, depth): url for url, depth in self.to_visit}
            while futures and self.should_continue():
                done, _ = concurrent.futures.wait(futures, timeout=1, return_when=concurrent.futures.FIRST_COMPLETED)
                for future in done:
                    futures.pop(future)
                    try:
                        new_urls = future.result()

                        for url, depth in new_urls:
                            if self.should_continue() and len(self.visited_urls) < self.max_pages:
                                futures[executor.submit(self.process_url, url, depth)] = url
                    except Exception as e:
                        logger.error(f"Error processing URL: {e}")

        logger.info(f"Crawled {len(self.visited_urls)} pages.")
        self.save_to_file()

    def should_continue(self):
        if self.max_duration > 0 and (time.time() - self.start_time) / 60 > self.max_duration:
            return False
        return True

    def process_url(self, url, depth):
        if not self.should_visit(url) or (self.max_depth > 0 and depth > self.max_depth):
            return []

        logger.info(f"Crawling: {url}")
        page_text, page_content = self.fetch_page(url)
        if not page_text:
            return []

        if self.max_parse_size > 0 and len(page_content) > self.max_parse_size:
            logger.info(f"Skipping {url} due to response size {len(page_content)} exceeding max_parse_size")
            return []

        self.visited_urls.add(url)
        links = self.extract_links(page_text, url)
        
        new_urls = []
        for link in links:
            if self.should_visit(link):
                new_urls.append((link, depth + 1))
            elif not self.is_same_domain(link):
                self.out_of_scope.add(link)

        if self.max_children > 0:
            new_urls = new_urls[:self.max_children]

        if self.process_forms:
            self.handle_forms(page_text, url)

        return new_urls

    def handle_forms(self, page_content, base_url):
        soup = BeautifulSoup(page_content, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            form_url = urljoin(base_url, action)
            form_data = {input_tag.get('name'): input_tag.get('value', '') for input_tag in form.find_all('input')}
            
            if method == 'post' and self.post_forms:
                self.submit_form(form_url, form_data, method='post')
            elif method == 'get':
                self.submit_form(form_url, form_data, method='get')

    def submit_form(self, url, data, method='get'):
        try:
            if method == 'post':
                response = self.session.post(url, data=data) if self.session else requests.post(url, data=data)
            else:
                response = self.session.get(url, params=data) if self.session else requests.get(url, params=data)
            response.raise_for_status()
            logger.info(f"Form submitted to {url} with method {method}")
        except requests.RequestException as e:
            logger.error(f"Form submission failed: {e}")

    def save_to_file(self):
        data = {
            'visited_urls': list(self.visited_urls),
            'out_of_scope_urls': list(self.out_of_scope)
        }
        with open(self.output_file, 'w') as f:
            json.dump(data, f, indent=4)
        logger.info(f"Saved crawled data to {self.output_file}")

# Usage example:
if __name__ == "__main__":
    spider = EnhancedWebSpider("https://testportal.helium.sh/", max_pages=100, max_depth=3, max_threads=10)
    spider.crawl()