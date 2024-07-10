import asyncio
import aiohttp
from aiohttp import ClientSession
from urllib.robotparser import RobotFileParser
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import logging
import json
import time
import re
from bloom_filter2 import BloomFilter
from newspaper import Article
from ratelimit import limits, sleep_and_retry

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class EnhancedWebSpider:
    def __init__(self, base_url, login_url=None, login_payload=None, max_pages=10, delay=1, retries=3,
                 output_file="crawled_data.json", respect_robots_txt=False, max_depth=0, max_threads=5,
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

        self.visited_urls = BloomFilter(max_elements=1000000, error_rate=0.1)
        self.visited_urls_set = set()  # Set to store visited URLs
        self.to_visit = asyncio.Queue()
        self.out_of_scope = set()
        self.start_time = None
        self.rp = RobotFileParser()

        self.visited_count = 0 

    async def login(self, session):
        if self.login_url and self.login_payload:
            try:
                async with session.post(self.login_url, data=self.login_payload) as response:
                    response.raise_for_status()
                    logger.info("Logged in successfully.")
            except aiohttp.ClientError as e:
                logger.error(f"Login failed: {e}")
                raise

    @sleep_and_retry
    @limits(calls=1, period=1)  # Rate limit: 1 request per second
    async def fetch_page(self, session, url):
        headers = {'Referer': url} if self.send_referer else {}
        for attempt in range(self.retries):
            try:
                async with session.get(url, headers=headers) as response:
                    response.raise_for_status()
                    content_type = response.headers.get('Content-Type', '').lower()
                    if 'text/html' in content_type:
                        return await response.text(), await response.read(), content_type
                    else:
                        return None, await response.read(), content_type
            except aiohttp.ClientError as e:
                logger.error(f"Failed to fetch {url} on attempt {attempt + 1}: {e}")
            await asyncio.sleep(self.delay)
        return None, None, None

    def extract_links(self, page_content, base_url):
        soup = BeautifulSoup(page_content, 'html.parser')
        links = set()

        for tag in soup.find_all(['a', 'link'], href=True):
            href = tag.get('href')
            full_url = urljoin(base_url, href)
            # Only include links that don't have file extensions typically used for non-HTML content
            if not re.search(r'\.(jpg|jpeg|png|gif|bmp|svg|mp3|mp4|pdf|doc|docx|xls|xlsx)$', full_url, re.IGNORECASE):
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

    def normalize_url(self, url):
        parsed = urlparse(url)
        # Remove default port
        netloc = parsed.netloc.replace(':80', '').replace(':443', '')
        # Normalize path
        path = parsed.path or '/'
        if path.endswith('/'):
            path = path[:-1]
        # Sort query parameters
        query = '&'.join(sorted(parsed.query.split('&')))
        return parsed._replace(netloc=netloc, path=path, query=query, fragment='').geturl()

    def is_valid_url(self, url):
        parsed_url = urlparse(url)
        return bool(parsed_url.scheme) and bool(parsed_url.netloc)

    def is_same_domain(self, url):
        parsed_url = urlparse(url)
        return urlparse(self.base_url).netloc == parsed_url.netloc

    async def read_robots_txt(self, session):
        robots_url = urljoin(self.base_url, "/robots.txt")
        try:
            async with session.get(robots_url) as response:
                if response.status == 200:
                    content = await response.text()
                    self.rp.parse(content.splitlines())
                else:
                    logger.info("No robots.txt found or inaccessible.")
        except aiohttp.ClientError as e:
            logger.error(f"Failed to fetch robots.txt: {e}")

    def is_allowed_by_robots(self, url):
        return self.rp.can_fetch("*", url)

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

    async def crawl(self):
        async with aiohttp.ClientSession() as session:
            if self.login_url and self.login_payload:
                await self.login(session)
            if self.respect_robots_txt:
                await self.read_robots_txt(session)

            self.start_time = time.time()
            await self.to_visit.put((self.base_url, 0))

            tasks = []
            for _ in range(self.max_threads):
                task = asyncio.create_task(self.worker(session))
                tasks.append(task)

            await self.to_visit.join()

            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"Crawled {self.visited_count} pages.")  # Use the counter
        self.save_to_file()

    def should_continue(self):
        if self.max_duration > 0 and (time.time() - self.start_time) / 60 > self.max_duration:
            return False
        return True

    async def worker(self, session):
        while self.should_continue():
            try:
                url, depth = await self.to_visit.get()
                await self.process_url(session, url, depth)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error processing URL: {e}")
            finally:
                self.to_visit.task_done()

    async def process_url(self, session, url, depth):
        if not self.should_visit(url) or (self.max_depth > 0 and depth > self.max_depth):
            return

        logger.info(f"Crawling: {url}")
        page_text, page_content, content_type = await self.fetch_page(session, url)
        
        if content_type and 'text/html' not in content_type:
            logger.info(f"Skipping non-HTML content: {url} (Content-Type: {content_type})")
            return

        if not page_text:
            return

        if self.max_parse_size > 0 and len(page_content) > self.max_parse_size:
            logger.info(f"Skipping {url} due to response size {len(page_content)} exceeding max_parse_size")
            return

        self.visited_urls.add(url)
        self.visited_urls_set.add(url)
        self.visited_count += 1
        links = self.extract_links(page_text, url)

        new_urls = []
        for link in links:
            if self.should_visit(link):
                new_urls.append((link, depth + 1))
            elif not self.is_same_domain(link):
                self.out_of_scope.add(link)

        if self.max_children > 0:
            new_urls = new_urls[:self.max_children]

        for new_url, new_depth in new_urls:
            await self.to_visit.put((new_url, new_depth))

        if self.process_forms:
            await self.handle_forms(session, page_text, url)

        # Basic content extraction using BeautifulSoup
        soup = BeautifulSoup(page_text, 'html.parser')
        title = soup.title.string if soup.title else "No title"
        main_content = soup.find('main') or soup.find('body')
        content_text = main_content.get_text(strip=True) if main_content else ""
        logger.info(f"Extracted page title: {title}")
        logger.info(f"Extracted content length: {len(content_text)}")

    async def handle_forms(self, session, page_content, base_url):
        soup = BeautifulSoup(page_content, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            form_url = urljoin(base_url, action)
            form_data = {input_tag.get('name'): input_tag.get('value', '') for input_tag in form.find_all('input')}
            
            if method == 'post' and self.post_forms:
                await self.submit_form(session, form_url, form_data, method='post')
            elif method == 'get':
                await self.submit_form(session, form_url, form_data, method='get')

    async def submit_form(self, session, url, data, method='get'):
        try:
            if method == 'post':
                async with session.post(url, data=data) as response:
                    response.raise_for_status()
            else:
                async with session.get(url, params=data) as response:
                    response.raise_for_status()
            logger.info(f"Form submitted to {url} with method {method}")
        except aiohttp.ClientError as e:
            logger.error(f"Form submission failed: {e}")

    def save_to_file(self):
        data = {
            'visited_urls': list(self.visited_urls_set),  # Use the set here
            'out_of_scope_urls': list(self.out_of_scope)
        }
        with open(self.output_file, 'w') as f:
            json.dump(data, f, indent=4)
        logger.info(f"Saved crawled data to {self.output_file}")

# Usage
async def main():
    spider = EnhancedWebSpider("https://testportal.helium.sh/")
    await spider.crawl()

if __name__ == "__main__":
    asyncio.run(main())