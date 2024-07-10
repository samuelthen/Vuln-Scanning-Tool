import yaml
import logging
import requests
import json
from requests.models import Request, Response
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
    
    if isinstance(value, dict):
        return value["value"]
    
    return value

if __name__ == '__main__':
    start_url = 'https://testportal.helium.sh/'  # Replace with the URL you want to start crawling
    urls, out_scope_urls = [start_url], []
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

            report_levels = [Risk.RISK_HIGH, Risk.RISK_MEDIUM, Risk.RISK_LOW]
            results = scanner.run_scan(request, response).values()
            
            for result in results:
                risk_level = result.risk_category.value[1].lower()

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
