import yaml
import logging
import requests
import json
from requests.models import Request, Response
from src.spider.web_spider import WebSpider
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scanner import PassiveScanner

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

with open('src/passive_scan/passive_scan_rules/utils/messages.yaml', 'r') as file:
    messages = yaml.safe_load(file)

def access_nested_dict(data, key_string):
    keys = key_string.split('.')
    value = data
    for key in keys:
        value = value[key]
    return value

if __name__ == '__main__':
    start_url = 'https://testportal.helium.sh/'  # Replace with the URL you want to start crawling
    spider = WebSpider(base_url=start_url, max_pages=1)
    urls, out_scope_urls = spider.crawl()
    crawl_results = {
        "in_scope_urls": urls,
        "out_scope_urls": out_scope_urls
    }

    scanner = PassiveScanner()
    ps_results = {"informational": {},
                  "low": {},
                  "medium": {},
                  "high": {}}

    for url in urls:
        try:
            request = Request(url=url)
            response = requests.get(url)
            # print(response.text)

            # report_levels = ["high", "medium", "low"]
            report_levels = [Risk.RISK_HIGH, Risk.RISK_MEDIUM, Risk.RISK_LOW]
            results = scanner.run_scan(request, response).values()
            
            for result in results:
                # print(access_nested_dict(messages, result.msg_ref + ".name"))
                
                risk_level = result.risk_category.value[1].lower()
                # print(risk_level)

                if result.risk_category == Risk.RISK_INFO:
                    msg = access_nested_dict(messages, result.msg_ref + ".name")
                    if msg not in ps_results[risk_level]:
                        ps_results[risk_level][msg] = [url]
                    else:
                        ps_results[risk_level][msg].append(url)
                
                elif result.risk_category in report_levels:
                    msg = access_nested_dict(messages, result.msg_ref + ".name")
                    output = {}
                    if result.evidence is not None:
                        output["evidence"] = result.evidence
                    if result.cwe_id is not None:
                        output["cwe_id"] = result.cwe_id
                    if result.wasc_id is not None:
                        output["wasc_id"] = result.wasc_id    

                    if msg not in ps_results[risk_level]:
                        ps_results[risk_level][msg] = {url: output}
                    else:
                        ps_results[risk_level][msg][url] = output

        except Exception as e:
            logger.error(e)
    
    data = {"urls": crawl_results, "passive_vulnerabilities": ps_results}
    with open("scan_results.json", 'w') as file:
        json.dump(data, file, indent=2)
    
    
    # with open('scan_results.csv', mode='w', newline='', encoding="utf-8") as file:
    #     all_tests = set().union(*(d.keys() for d in ps_results))

    #     fieldnames = ['Index', 'URL'] + list(all_tests)
    #     writer = csv.DictWriter(file, fieldnames=fieldnames)

    #     writer.writeheader()
    #     for index, (url, result) in enumerate(zip(urls, ps_results), start=1):
    #         row = {'Index': index, 'URL': url}
    #         row.update(result)
    #         writer.writerow(row)
    