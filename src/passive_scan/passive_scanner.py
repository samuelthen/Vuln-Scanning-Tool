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
from src.passive_scan.passive_scan_rules.insecure_form_load_scan_rule import InsecureFormLoadScanRule
from src.passive_scan.passive_scan_rules.insecure_form_post_scan_rule import InsecureFormPostScanRule
from src.passive_scan.passive_scan_rules.cookie_http_only_scan_rule import CookieHttpOnlyScanRule
from src.passive_scan.passive_scan_rules.csrf_countermeasures_scan_rule import CsrfCountermeasuresScanRule
from src.passive_scan.passive_scan_rules.information_disclosure_in_url_scan_rule import InformationDisclosureInUrlScanRule
from src.passive_scan.passive_scan_rules.information_disclosure_referrer_scan_rule import InformationDisclosureReferrerScanRule
from src.passive_scan.passive_scan_rules.cookie_loosely_scoped_scan_rule import CookieLooselyScopedScanRule
from src.passive_scan.passive_scan_rules.cookie_same_site_scan_rule import CookieSameSiteScanRule
from src.passive_scan.passive_scan_rules.hash_disclosure_scan_rule import HashDisclosureScanRule
from src.passive_scan.passive_scan_rules.user_controlled_cookie_scan_rule import UserControlledCookieScanRule
from src.passive_scan.passive_scan_rules.x_content_type_options_scan_rule import XContentTypeOptionsScanRule
from src.passive_scan.passive_scan_rules.x_powered_by_header_info_leak_scan_rule import XPoweredByHeaderInfoLeakScanRule
from src.passive_scan.passive_scan_rules.big_redirects_scan_rule import BigRedirectsScanRule
from src.passive_scan.passive_scan_rules.cache_control_scan_rule import CacheControlScanRule
from src.passive_scan.passive_scan_rules.content_type_missing_scan_rule import ContentTypeMissingScanRule
from src.passive_scan.passive_scan_rules.cross_domain_misconfiguration_scan_rule import CrossDomainMisconfigurationScanRule
from src.passive_scan.passive_scan_rules.directory_browsing_scan_rule import DirectoryBrowsingScanRule
from src.passive_scan.passive_scan_rules.heart_bleed_scan_rule import HeartBleedScanRule
from src.passive_scan.passive_scan_rules.insecure_authentication_scan_rule import InsecureAuthenticationScanRule
from src.passive_scan.passive_scan_rules.insecure_jsf_view_state_passive_scan_rule import InsecureJsfViewStatePassiveScanRule
from src.passive_scan.passive_scan_rules.mixed_content_scan_rule import MixedContentScanRule
from src.passive_scan.passive_scan_rules.server_header_info_leak_scan_rule import ServerHeaderInfoLeakScanRule
from src.passive_scan.passive_scan_rules.x_asp_net_version_scan_rule import XAspNetVersionScanRule
from src.passive_scan.passive_scan_rules.x_backend_server_information_leak_scan_rule import XBackendServerInformationLeakScanRule
from src.passive_scan.passive_scan_rules.x_chrome_logger_data_info_leak_scan_rule import XChromeLoggerDataInfoLeakScanRule
from src.passive_scan.passive_scan_rules.x_debug_token_scan_rule import XDebugTokenScanRule

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

        # self.scan_rules.append(AntiClickjackingScanRule())
        # self.scan_rules.append(ContentSecurityPolicyMissingScanRule())
        # self.scan_rules.append(CrossDomainScriptInclusionScanRule())
        # self.scan_rules.append(StrictTransportSecurityScanRule())
        # self.scan_rules.append(ApplicationErrorScanRule())
        # self.scan_rules.append(CookieSecureFlagScanRule())
        # self.scan_rules.append(UserControlledHTMLAttributesScanRule())
        # self.scan_rules.append(UserControlledJavascriptEventScanRule())
        # self.scan_rules.append(InsecureFormLoadScanRule())
        # self.scan_rules.append(InsecureFormPostScanRule())
        # self.scan_rules.append(CookieHttpOnlyScanRule())
        # self.scan_rules.append(CsrfCountermeasuresScanRule())
        # self.scan_rules.append(InformationDisclosureInUrlScanRule())
        # self.scan_rules.append(InformationDisclosureReferrerScanRule())
        # self.scan_rules.append(CookieSameSiteScanRule())
        # self.scan_rules.append(CookieLooselyScopedScanRule())
        # self.scan_rules.append(HashDisclosureScanRule()) 
        # self.scan_rules.append(UserControlledCookieScanRule())
        # self.scan_rules.append(XContentTypeOptionsScanRule())
        # self.scan_rules.append(XPoweredByHeaderInfoLeakScanRule())
        # self.scan_rules.append(BigRedirectsScanRule())
        # self.scan_rules.append(CacheControlScanRule())
        # self.scan_rules.append(ContentTypeMissingScanRule())
        # self.scan_rules.append(CrossDomainMisconfigurationScanRule())
        # self.scan_rules.append(DirectoryBrowsingScanRule())
        # self.scan_rules.append(HeartBleedScanRule())
        # self.scan_rules.append(InsecureAuthenticationScanRule())
        # self.scan_rules.append(InsecureJsfViewStatePassiveScanRule()) #Error
        # self.scan_rules.append(MixedContentScanRule()) #Error
        # self.scan_rules.append(ServerHeaderInfoLeakScanRule())
        self.scan_rules.append(XAspNetVersionScanRule())
        self.scan_rules.append(XBackendServerInformationLeakScanRule()) 
        self.scan_rules.append(XChromeLoggerDataInfoLeakScanRule())
        self.scan_rules.append(XDebugTokenScanRule())


    def run_scan(self, request: Request, response: Response) -> List[Alert]:
        """Run the vulnerability scan."""
        results = {}
        logger.info(f"Scanning: {request.url}")

        for scan_rule in self.scan_rules:
            try:
                result = scan_rule.check_risk(request, response)
                results[str(scan_rule)] = result
                print(str(result))
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
