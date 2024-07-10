import requests
from bs4 import BeautifulSoup
import concurrent.futures
import time
import re
from urllib.parse import urljoin, urlparse, parse_qs

class Spider:
    def __init__(self, 
                 max_depth=0, 
                 max_threads=5, 
                 max_duration=0, 
                 max_children=0, 
                 max_parse_size=0, 
                 domains_in_scope=None, 
                 query_param_handling=2, 
                 send_referer=False, 
                 accept_cookies=True, 
                 process_forms=True, 
                 post_forms=False, 
                 parse_html_comments=False, 
                 parse_robots_txt=False, 
                 parse_sitemap_xml=False, 
                 parse_svn_metadata=False, 
                 parse_git_metadata=False, 
                 parse_ds_store_files=False, 
                 handle_odata_params=False, 
                 irrelevant_params=None):
        
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
        self.session = requests.Session() if self.accept_cookies else None
        self.start_time = None
        
    def crawl(self, start_url):
        self.start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.process_url, start_url, 0): start_url}
            while futures:
                done, _ = concurrent.futures.wait(futures, timeout=1, return_when=concurrent.futures.FIRST_COMPLETED)
                for future in done:
                    futures.pop(future)
                    try:
                        urls = future.result()
                        for url, depth in urls:
                            if self.should_continue():
                                futures[executor.submit(self.process_url, url, depth)] = url
                    except Exception as e:
                        print(f"Error processing URL: {e}")

    def should_continue(self):
        if self.max_duration > 0 and (time.time() - self.start_time) / 60 > self.max_duration:
            return False
        return True

    def process_url(self, url, depth):
        if url in self.visited_urls or (self.max_depth > 0 and depth > self.max_depth):
            return []
        
        self.visited_urls.add(url)
        
        headers = {'Referer': url} if self.send_referer else {}
        response = self.session.get(url, headers=headers) if self.session else requests.get(url, headers=headers)
        
        if response.status_code != 200:
            print(f"Failed to retrieve {url}: Status code {response.status_code}")
            return []

        if self.max_parse_size > 0 and len(response.content) > self.max_parse_size:
            print(f"Skipping {url} due to response size {len(response.content)} exceeding max_parse_size")
            return []

        if self.domains_in_scope and not any(re.match(domain, url) for domain in self.domains_in_scope):
            print(f"Skipping {url} as it is out of scope")
            return []

        soup = BeautifulSoup(response.content, 'html.parser')
        links = self.extract_links(soup, url)

        return [(link, depth + 1) for link in links]

    def extract_links(self, soup, base_url):
        links = set()
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = urljoin(base_url, href)
            if self.should_visit(full_url):
                links.add(full_url)
                print(f"Found link: {full_url}")
        return links

    def should_visit(self, url):
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        if self.query_param_handling == 0:
            url = url.split('?')[0]
        elif self.query_param_handling == 1:
            url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?" + '&'.join(params.keys())
        elif self.handle_odata_params:
            url = self.handle_odata_url(url, params)
        
        return url not in self.visited_urls

    def handle_odata_url(self, url, params):
        for param in self.irrelevant_params:
            if param in params:
                params.pop(param)
        return f"{url.split('?')[0]}?" + '&'.join(f"{key}={value[0]}" for key, value in params.items())

# Example usage:
spider = Spider(max_depth=2, max_threads=10, domains_in_scope=["https://testportal.helium.sh/"], query_param_handling=1, accept_cookies=True)
spider.crawl("https://testportal.helium.sh/")
