import csv
import requests
from requests.models import Request, Response

from src.spider.web_spider import WebSpider
from src.passive_scan.passive_scanner import PassiveScanner

if __name__ == '__main__':
    start_url = 'https://en.wikipedia.org/wiki/Web_scraping'  # Replace with the URL you want to start crawling
    
    spider = WebSpider(base_url=start_url, max_pages=20)
    urls = spider.crawl()
    
    scanner = PassiveScanner()
    ps_results = []

    for url in urls:
        request = Request(url=url)
        response = requests.get(url)
        ps_results.append(scanner.run_scan(request, response))

    with open('scan_results.csv', mode='w', newline='', encoding="utf-8") as file:
        all_tests = set().union(*(d.keys() for d in ps_results))

        fieldnames = ['Index', 'URL'] + list(all_tests)
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        writer.writeheader()
        for index, (url, result) in enumerate(zip(urls, ps_results), start=1):
            row = {'Index': index, 'URL': url}
            row.update(result)
            writer.writerow(row)
    