import yaml
import logging
import json
import argparse
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scanner import PassiveScanner
from src.spider.spider import EnhancedWebSpider

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

with open('src/passive_scan/passive_scan_rules/utils/messages.yaml', 'r') as file:
    messages = yaml.safe_load(file)

def access_nested_dict(data, key_string):
    keys = key_string.split('.')
    value = data
    for key in keys:
        if key in value:
            value = value[key]
        else:
            return None
    
    if isinstance(value, dict):
        return value.get("value", None)
    
    return value

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Web Spider and Passive Scanner")
    parser.add_argument('-url', type=str, required=True, help='URL to start crawling')
    args = parser.parse_args()
    
    start_url = args.url
    
    spider = EnhancedWebSpider(start_url, max_pages=10, max_depth=2, 
                               max_threads=10, query_param_handling=2)
    spider.crawl()
    urls, out_scope_urls = list(spider.visited_urls), list(spider.out_of_scope)
    urls.sort()
    out_scope_urls.sort()

    crawl_results = {
        "in_scope_urls": urls,
        "out_scope_urls": out_scope_urls
    }

    scanner = PassiveScanner()
    ps_results = {"informational": {},
                  "low": {},
                  "medium": {},
                  "high": {}}

    methods = ["GET", "POST"]

    for url in urls:
        try:
            for method in methods:
                request, response = spider.url_request_response_map[f"{method} {url}"]

                report_levels = [Risk.RISK_HIGH, Risk.RISK_MEDIUM, Risk.RISK_LOW, Risk.RISK_INFO]
                results = scanner.run_scan(request, response).values()
                
                for result in results:
                    risk_level = result.risk_category.value[1].lower()

                    if result.risk_category in report_levels:
                        msg = access_nested_dict(messages, result.msg_ref + ".name")
                        
                        output = {}
                        
                        output['url'] = url

                        if result.evidence is not None:
                            output["evidence"] = result.evidence
                    
                        output['method'] = request.method

                        if msg not in ps_results[risk_level]:

                            ps_results[risk_level][msg] = {}
                            
                            desc = access_nested_dict(messages, result.msg_ref + ".desc")
                            if desc is not None:
                                ps_results[risk_level][msg]["description"] = desc
                            
                            soln = access_nested_dict(messages, result.msg_ref + ".soln")
                            if soln is not None:
                                ps_results[risk_level][msg]["solution"] = soln
                            
                            if result.cwe_id is not None:
                                ps_results[risk_level][msg]["cwe_id"] = result.cwe_id

                            if result.wasc_id is not None:
                                ps_results[risk_level][msg]["wasc_id"] = result.wasc_id    

                            refs = access_nested_dict(messages, result.msg_ref + ".refs")
                            if refs is not None:
                                ps_results[risk_level][msg]["reference"] = refs

                            ps_results[risk_level][msg]["instance"] = [output]

                        else:
                            ps_results[risk_level][msg]["instance"].append(output)

        except Exception as e:
            logger.error(e)

    data = {"urls": crawl_results, "passive_vulnerabilities": ps_results}
    with open("scan_results.json", 'w') as file:
        json.dump(data, file, indent=2)
