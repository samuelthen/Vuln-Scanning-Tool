import logging
from typing import List
from requests.models import Request, Response
from .passive_scan_rules.utils.base_passive_scan_rule import BasePassiveScanRule
from .passive_scan_rules.utils.base_passive_scan_rule import Alert
from .passive_scan_rules.anticlickjacking_scan_rule import AntiClickjackingScanRule
from .passive_scan_rules.content_security_policy_missing_scan_rule import ContentSecurityPolicyMissingScanRule
from .passive_scan_rules.cross_domain_script_inclusion_scan_rule import CrossDomainScriptInclusionScanRule
from .passive_scan_rules.strict_transport_security_scan_rule import StrictTransportSecurityScanRule
from .passive_scan_rules.application_error_scan_rule import ApplicationErrorScanRule
from .passive_scan_rules.cookie_secure_flag_scan_rule import CookieSecureFlagScanRule
from .passive_scan_rules.user_controlled_html_attributes_scan_rule import UserControlledHTMLAttributesScanRule
from .passive_scan_rules.user_controlled_javascript_event_scan_rule import UserControlledJavascriptEventScanRule
from .passive_scan_rules.insecure_form_load_scan_rule import InsecureFormLoadScanRule
from .passive_scan_rules.insecure_form_post_scan_rule import InsecureFormPostScanRule
from .passive_scan_rules.cookie_http_only_scan_rule import CookieHttpOnlyScanRule
from .passive_scan_rules.csrf_countermeasures_scan_rule import CsrfCountermeasuresScanRule
from .passive_scan_rules.information_disclosure_in_url_scan_rule import InformationDisclosureInUrlScanRule
from .passive_scan_rules.information_disclosure_referrer_scan_rule import InformationDisclosureReferrerScanRule
from .passive_scan_rules.cookie_loosely_scoped_scan_rule import CookieLooselyScopedScanRule
from .passive_scan_rules.cookie_same_site_scan_rule import CookieSameSiteScanRule
from .passive_scan_rules.hash_disclosure_scan_rule import HashDisclosureScanRule
from .passive_scan_rules.user_controlled_cookie_scan_rule import UserControlledCookieScanRule
from .passive_scan_rules.x_content_type_options_scan_rule import XContentTypeOptionsScanRule
from .passive_scan_rules.x_powered_by_header_info_leak_scan_rule import XPoweredByHeaderInfoLeakScanRule
from .passive_scan_rules.big_redirects_scan_rule import BigRedirectsScanRule
from .passive_scan_rules.cache_control_scan_rule import CacheControlScanRule
from .passive_scan_rules.content_type_missing_scan_rule import ContentTypeMissingScanRule
from .passive_scan_rules.cross_domain_misconfiguration_scan_rule import CrossDomainMisconfigurationScanRule
from .passive_scan_rules.directory_browsing_scan_rule import DirectoryBrowsingScanRule
from .passive_scan_rules.heart_bleed_scan_rule import HeartBleedScanRule
from .passive_scan_rules.insecure_authentication_scan_rule import InsecureAuthenticationScanRule
from .passive_scan_rules.insecure_jsf_view_state_passive_scan_rule import InsecureJsfViewStatePassiveScanRule
from .passive_scan_rules.mixed_content_scan_rule import MixedContentScanRule
from .passive_scan_rules.server_header_info_leak_scan_rule import ServerHeaderInfoLeakScanRule
from .passive_scan_rules.x_asp_net_version_scan_rule import XAspNetVersionScanRule
from .passive_scan_rules.x_backend_server_information_leak_scan_rule import XBackendServerInformationLeakScanRule
from .passive_scan_rules.x_chrome_logger_data_info_leak_scan_rule import XChromeLoggerDataInfoLeakScanRule
from .passive_scan_rules.x_debug_token_scan_rule import XDebugTokenScanRule
from .passive_scan_rules.content_security_policy_scan_rule import ContentSecurityPolicyScanRule
from .passive_scan_rules.information_disclosure_debug_errors_scan_rule import InformationDisclosureDebugErrorsScanRule
from .passive_scan_rules.information_disclosure_suspicious_comments_scan_rule import InformationDisclosureSuspiciousCommentsScanRule
from .passive_scan_rules.charset_mismatch_scan_rule import CharsetMismatchScanRule
from .passive_scan_rules.info_private_address_disclosure_scan_rule import InfoPrivateAddressDisclosureScanRule
from .passive_scan_rules.info_session_id_url_scan_rule import InfoSessionIdUrlScanRule
from .passive_scan_rules.link_target_scan_rule import LinkTargetScanRule
from .passive_scan_rules.modern_app_detection_scan_rule import ModernAppDetectionScanRule
from .passive_scan_rules.pii_scan_rule import PiiScanRule
from .passive_scan_rules.retrieved_from_cache_scan_rule import RetrievedFromCacheScanRule
from .passive_scan_rules.timestamp_disclosure_scan_rule import TimestampDisclosureScanRule
from .passive_scan_rules.user_controlled_charset_scan_rule import UserControlledCharsetScanRule
from .passive_scan_rules.user_controlled_open_redirect_scan_rule import UserControlledOpenRedirectScanRule
from .passive_scan_rules.username_idor_scan_rule import UsernameIdorScanRule
from .passive_scan_rules.viewstate_scan_rule import ViewstateScanRule

logger = logging.getLogger(__name__)

class PassiveScanner:
    """Passive scanner class for vulnerability scanning."""
    def __init__(self):
        """
        Initialize the PassiveScanner.

        :param request: The request object.
        :param response: The response object.
        """
        self.scan_rules: List[BasePassiveScanRule] = [
            AntiClickjackingScanRule(),
            ContentSecurityPolicyMissingScanRule(),
            CrossDomainScriptInclusionScanRule(),
            StrictTransportSecurityScanRule(),
            ApplicationErrorScanRule(),
            CookieSecureFlagScanRule(),
            UserControlledHTMLAttributesScanRule(),
            UserControlledJavascriptEventScanRule(),
            InsecureFormLoadScanRule(),
            InsecureFormPostScanRule(),
            CookieHttpOnlyScanRule(),
            CsrfCountermeasuresScanRule(),
            InformationDisclosureInUrlScanRule(),
            InformationDisclosureReferrerScanRule(),
            CookieSameSiteScanRule(),
            CookieLooselyScopedScanRule(),
            HashDisclosureScanRule(),
            UserControlledCookieScanRule(),
            XContentTypeOptionsScanRule(),
            XPoweredByHeaderInfoLeakScanRule(),
            BigRedirectsScanRule(),
            CacheControlScanRule(),
            ContentTypeMissingScanRule(),
            CrossDomainMisconfigurationScanRule(),
            DirectoryBrowsingScanRule(),
            HeartBleedScanRule(),
            InsecureAuthenticationScanRule(),
            InsecureJsfViewStatePassiveScanRule(),
            MixedContentScanRule(),
            ServerHeaderInfoLeakScanRule(),
            XAspNetVersionScanRule(),
            XBackendServerInformationLeakScanRule(),
            XChromeLoggerDataInfoLeakScanRule(),
            XDebugTokenScanRule(),
            ContentSecurityPolicyScanRule(),
            InformationDisclosureDebugErrorsScanRule(),
            InformationDisclosureSuspiciousCommentsScanRule(),
            CharsetMismatchScanRule(),
            InfoPrivateAddressDisclosureScanRule(),
            InfoSessionIdUrlScanRule(),
            LinkTargetScanRule(),
            ModernAppDetectionScanRule(),
            PiiScanRule(),
            RetrievedFromCacheScanRule(),
            TimestampDisclosureScanRule(),
            UserControlledCharsetScanRule(),
            UserControlledOpenRedirectScanRule(),
            UsernameIdorScanRule(),
            ViewstateScanRule()
        ]

    def run_scan(self, request: Request, response: Response) -> List[Alert]:
        """Run the vulnerability scan."""
        results = {}
        logger.info(f"Scanning: {request.url}")

        for scan_rule in self.scan_rules:
            try:
                result = scan_rule.check_risk(request, response)
                results[str(scan_rule)] = result

            except Exception as e:
                
                logger.error(e)

        return results
