import logging
import yaml
from typing import List
import requests
from requests.models import Request, Response
from src.passive_scan.passive_scan_rules.utils.base_passive_scan_rule import BasePassiveScanRule
from src.passive_scan.passive_scan_rules.utils.base_passive_scan_rule import Alert
from src.passive_scan.passive_scan_rules.anticlickjacking_scan_rule import AntiClickjackingScanRule
from src.passive_scan.passive_scan_rules.content_security_policy_missing_scan_rule import ContentSecurityPolicyMissingScanRule
from src.passive_scan.passive_scan_rules.cross_domain_script_inclusion_scan_rule import CrossDomainScriptInclusionScanRule
from src.passive_scan.passive_scan_rules.strict_transport_security_scan_rule import StrictTransportSecurityScanRule
from src.passive_scan.passive_scan_rules.application_error_scan_rule import ApplicationErrorScanRule
from src.passive_scan.passive_scan_rules.cookie_secure_flag_scan_rule import CookieSecureFlagScanRule
from src.passive_scan.passive_scan_rules.user_controlled_html_attributes_scan_rule import UserControlledHTMLAttributesScanRule
from src.passive_scan.passive_scan_rules.user_controlled_javascript_event_scan_rule import UserControlledJavascriptEventScanRule
# from passive_scan_rules.utils.base_passive_scan_rule import BasePassiveScanRule
# from passive_scan_rules.anticlickjacking_scan_rule import AntiClickjackingScanRule
# from passive_scan_rules.content_security_policy_missing_scan_rule import ContentSecurityPolicyMissingScanRule
# from passive_scan_rules.cross_domain_script_inclusion_scan_rule import CrossDomainScriptInclusionScanRule
# from passive_scan_rules.strict_transport_security_scan_rule import StrictTransportSecurityScanRule
# from passive_scan_rules.application_error_scan_rule import ApplicationErrorScanRule
# from passive_scan_rules.cookie_secure_flag_scan_rule import CookieSecureFlagScanRule
# from passive_scan_rules.user_controlled_html_attributes_scan_rule import UserControlledHTMLAttributesScanRule
# from passive_scan_rules.user_controlled_javascript_event_scan_rule import UserControlledJavascriptEventScanRule

logger = logging.getLogger(__name__)

class PassiveScanner:
    """Passive scanner class for vulnerability scanning."""
    def __init__(self):
        """
        Initialize the PassiveScanner.

        :param request: The request object.
        :param response: The response object.
        """
        self.scan_rules: List[BasePassiveScanRule] = []

        self.scan_rules.append(AntiClickjackingScanRule())
        self.scan_rules.append(ContentSecurityPolicyMissingScanRule())
        self.scan_rules.append(CrossDomainScriptInclusionScanRule())
        self.scan_rules.append(StrictTransportSecurityScanRule())
        self.scan_rules.append(ApplicationErrorScanRule())
        self.scan_rules.append(CookieSecureFlagScanRule())
        self.scan_rules.append(UserControlledHTMLAttributesScanRule())
        self.scan_rules.append(UserControlledJavascriptEventScanRule())

    def run_scan(self, request: Request, response: Response) -> List[Alert]:
        """Run the vulnerability scan."""
        results = {}

        for scan_rule in self.scan_rules:
            try:
                results[str(scan_rule)] = scan_rule.check_risk(request, response)
            except Exception as e:
                
                logger.error(e)

        return results

def access_nested_dict(data, key_string):
    keys = key_string.split('.')
    value = data
    for key in keys:
        value = value[key]
    return value

if __name__ == '__main__':

    url = "https://testportal.helium.sh"  # Replace with the URL you want to start crawling
    request = Request(url=url)

    with open('src/passive_scan/passive_scan_rules/utils/messages.yaml', 'r') as file:
        messages = yaml.safe_load(file)

    try:
        response = requests.get(url)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error making request: {e}")
        response = None

    if response:
        scanner = PassiveScanner()
        report_levels = ["high", "medium", "low", "informational"]
        results = scanner.run_scan(request, response).values()
        
        for result in results:
            # print(str(result))
            if result.risk_category in report_levels:
                print(result.risk_category)
                print(access_nested_dict(messages, result.msg_ref + ".name"))
