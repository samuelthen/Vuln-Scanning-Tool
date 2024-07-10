import requests
from requests.models import Request
import time
import logging
import json
import re
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin, urlparse, parse_qs
from random import uniform
from collections import deque
import concurrent.futures

logger = logging.getLogger(__name__)

class EnhancedWebSpider:
    """
    A web crawler (spider) that navigates through web pages starting from a base URL and extracts links and data.
    """
    
    def __init__(self, base_url, login_url=None, login_payload=None, max_pages=10, delay=1, retries=3,
                 output_file="crawled_data.json", respect_robots_txt=False, max_depth=0, max_threads=5,
                 max_duration=0, max_children=0, max_parse_size=0, domains_in_scope=None,
                 query_param_handling=2, send_referer=False, accept_cookies=True, process_forms=True,
                 post_forms=False, parse_html_comments=False, 
                 parse_sitemap_xml=False, parse_svn_metadata=False, parse_git_metadata=False,
                 parse_ds_store_files=False, handle_odata_params=False, irrelevant_params=None):
        """
        Initializes the EnhancedWebSpider with the given configuration.
        """
        
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
        self.parse_sitemap_xml = parse_sitemap_xml
        self.parse_svn_metadata = parse_svn_metadata
        self.parse_git_metadata = parse_git_metadata
        self.parse_ds_store_files = parse_ds_store_files
        self.handle_odata_params = handle_odata_params
        self.irrelevant_params = irrelevant_params or []
        self.url_request_response_map = {}

        self.visited_urls = set()
        self.to_visit = deque([(base_url, 0)])  # Use a deque for BFS
        self.out_of_scope = set()
        self.session = requests.Session() if self.accept_cookies else None
        self.session.headers.update({'User-Agent': 'EnhancedWebSpider/1.0'})
        self.robots_txt = None
        self.disallowed_paths = []
        self.start_time = None

        self.extract_domain_and_add_to_scope(base_url)

    def extract_domain_and_add_to_scope(self, url):
        """
        Extracts the domain from the given URL and adds it to the list of domains in scope.
        """
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        if domain not in self.domains_in_scope:
            self.domains_in_scope.append(domain)

    def login(self):
        """
        Logs in to the website using the provided login URL and payload.
        """
        if self.login_url and self.login_payload:
            try:
                response = self.session.post(self.login_url, data=self.login_payload)
                response.raise_for_status()
                logger.debug("Logged in successfully.")
            except requests.RequestException as e:
                logger.error(f"Login failed: {e}")
                raise

    def extract_links(self, page_content, base_url):
        """
        Extracts all links from the given page content.
        """
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
            comments = soup.find_all(string=lambda text: isinstance(text, Comment))
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
        """
        Extracts all links from the given text.
        """
        links = set()
        for match in re.findall(r'(https?://\S+)', text):
            full_url = urljoin(base_url, match)
            links.add(self.normalize_url(full_url))
        return links

    def normalize_url(self, url):
        """
        Normalizes the given URL by removing the fragment.
        """
        parsed_url = urlparse(url)
        return parsed_url._replace(fragment='').geturl()

    def is_valid_url(self, url):
        """
        Checks if the given URL is valid.
        """
        parsed_url = urlparse(url)
        return bool(parsed_url.scheme) and bool(parsed_url.netloc)

    def is_domain_in_scope(self, url):
        """
        Checks if the domain of the given URL is in scope.
        """
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        for scoped_domain in self.domains_in_scope:
            if domain == scoped_domain:
                return True
        return False

    def read_robots_txt(self):
        """
        Reads and parses the robots.txt file for the base URL.
        """
        robots_url = urljoin(self.base_url, "/robots.txt")
        try:
            response = self.session.get(robots_url) if self.session else requests.get(robots_url)
            if response.status_code == 200:
                self.robots_txt = response.text
                self.parse_robots_txt()
            else:
                logger.debug("No robots.txt found or inaccessible.")
        except requests.RequestException as e:
            logger.error(f"Failed to fetch robots.txt: {e}")

    def parse_robots_txt(self):
        """
        Parses the robots.txt file to extract disallowed paths.
        """
        if self.robots_txt:
            for line in self.robots_txt.split("\n"):
                if line.strip().startswith("Disallow"):
                    path = line.split(":")[1].strip()
                    self.disallowed_paths.append(path)

    def is_allowed_by_robots(self, url):
        """
        Checks if the given URL is allowed by the robots.txt file.
        """
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
            normalized_url = url.split('?')[0]
        elif self.query_param_handling == 1:
            normalized_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?" + '&'.join(params.keys())
        else:  # self.query_param_handling == 2 or other cases
            normalized_url = url

        if self.handle_odata_params:
            normalized_url = self.handle_odata_url(normalized_url, params)

        return (
            normalized_url not in self.visited_urls and
            self.is_valid_url(normalized_url) and
            self.is_domain_in_scope(normalized_url) and
            (not self.respect_robots_txt or self.is_allowed_by_robots(normalized_url))
        )

    def handle_odata_url(self, url, params):
        """
        Handles OData parameters in the given URL.
        """
        for param in self.irrelevant_params:
            if param in params:
                params.pop(param)
        return f"{url.split('?')[0]}?" + '&'.join(f"{key}={value[0]}" for key, value in params.items())

    def fetch_page(self, url):
        """
        Fetches the content of the given URL.
        """
        headers = {'Referer': url} if self.send_referer else {}
        for attempt in range(self.retries):
            try:
                # Create the request
                req = Request('GET', url, headers=headers)
                
                # Send the request
                response = self.session.send(req.prepare()) if self.session else requests.Session().send(req.prepare())
                response.raise_for_status()
                
                # Store the request and response in the mapping
                self.url_request_response_map[url] = (req, response)
                
                return response.text, response.content
            except requests.RequestException as e:
                logger.debug(f"Failed to fetch {url} on attempt {attempt + 1}: {e}")
                time.sleep(self.delay * uniform(0.5, 1.5))  # Randomize delay to be more polite
        return None, None

    def crawl(self):
        """
        Starts the crawling process.
        """
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
                            if self.should_continue() and len(self.visited_urls) < self.max_pages and (self.max_depth == 0 or depth <= self.max_depth):
                                futures[executor.submit(self.process_url, url, depth)] = url
                            else:
                                break
                    except Exception as e:
                        logger.error(f"Error processing URL: {e}")

        logger.info(f"Crawled {len(self.visited_urls)} pages.")

    def process_url(self, url, depth):
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        if self.query_param_handling == 0:
            normalized_url = url.split('?')[0]
        elif self.query_param_handling == 1:
            normalized_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?" + '&'.join(params.keys())
        else:
            normalized_url = url

        if self.handle_odata_params:
            normalized_url = self.handle_odata_url(normalized_url, params)

        if not self.should_visit(normalized_url) or len(self.visited_urls) >= self.max_pages:
            return []

        logger.info(f"Crawling: {normalized_url}")
        page_text, page_content = self.fetch_page(normalized_url)
        if not page_text:
            return []

        if self.max_parse_size > 0 and len(page_content) > self.max_parse_size:
            logger.debug(f"Skipping {normalized_url} due to response size {len(page_content)} exceeding max_parse_size")
            return []

        self.visited_urls.add(normalized_url)
        links = self.extract_links(page_text, normalized_url)

        new_urls = []
        for link in links:
            if self.should_visit(link):
                new_urls.append((link, depth + 1))
            elif not self.is_domain_in_scope(link):
                self.out_of_scope.add(link)

        if self.max_children > 0:
            new_urls = new_urls[:self.max_children]

        if self.process_forms:
            self.handle_forms(page_text, normalized_url)

        return new_urls


    def should_continue(self):
        """
        Determines if the crawling should continue based on duration and page limits.
        """
        if self.max_duration > 0 and (time.time() - self.start_time) / 60 > self.max_duration:
            return False
        if len(self.visited_urls) >= self.max_pages:
            return False
        return True

    def handle_forms(self, page_content, base_url):
        """
        Handles forms found on the given page content.
        """
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
        """
        Submits a form with the given data to the specified URL using the specified method.
        """
        try:
            if method == 'post':
                response = self.session.post(url, data=data) if self.session else requests.post(url, data=data)
            else:
                response = self.session.get(url, params=data) if self.session else requests.get(url, params=data)
            response.raise_for_status()
            logger.debug(f"Form submitted to {url} with method {method}")
        except requests.RequestException as e:
            logger.error(f"Form submission failed: {e}")