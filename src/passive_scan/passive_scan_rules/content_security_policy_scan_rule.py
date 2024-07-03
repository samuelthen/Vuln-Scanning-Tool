import logging
from typing import List, Optional, Dict
from bs4 import BeautifulSoup
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class ContentSecurityPolicyScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for Content Security Policy issues.
    """
    MSG_REF = "pscanrules.csp"
    RISK = Risk.RISK_MEDIUM 
    CONFIDENCE = Confidence.CONFIDENCE_HIGH

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
        CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG
    ]
    
    HTTP_HEADER_XCSP = "X-Content-Security-Policy"
    HTTP_HEADER_WEBKIT_CSP = "X-WebKit-CSP"
    
    DIRECTIVES_WITHOUT_FALLBACK = [
        "base-uri",
        "form-action",
        "frame-ancestors",
        "plugin-types",
        "report-uri",
        "sandbox"
    ]
    
    ALLOWED_DIRECTIVES = ["require-trusted-types-for", "trusted-types"]

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for Content Security Policy issues in the response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            csp_header_found = False
            csp_options = response.headers.get('Content-Security-Policy')

            if csp_options:
                csp_header_found = True

            self.check_xcsp(response, csp_header_found)
            self.check_xwebkit_csp(response, csp_header_found)

            if csp_header_found:
                observed_errors = []
                for csp in csp_options.split(','):
                    policy = self.parse_policy(csp, observed_errors, request, response)
                    if policy is None:
                        continue

                    if observed_errors:
                        self.check_observed_errors(observed_errors, request, response, csp, False)

                    allowed_wildcard_sources = self.get_allowed_wildcard_sources(csp)
                    if allowed_wildcard_sources:
                        self.check_wildcard_sources(allowed_wildcard_sources, request, response, csp, False)

                    # Further checks based on policy...
                    if policy.allows_unsafe_inline_script():
                        self.build_script_unsafe_inline_alert("Content-Security-Policy", csp)
                    
                    if policy.allows_unsafe_inline_style():
                        self.build_style_unsafe_inline_alert("Content-Security-Policy", csp)
                    
                    if policy.allows_unsafe_hashes("script-src"):
                        self.build_script_unsafe_hash_alert("Content-Security-Policy", csp)
                    
                    if policy.allows_unsafe_hashes("style-src"):
                        self.build_style_unsafe_hash_alert("Content-Security-Policy", csp)
                    
                    if policy.allows_unsafe_eval("script-src"):
                        self.build_script_unsafe_eval_alert("Content-Security-Policy", csp)

            if self.has_meta_csp(response.text):
                self.check_meta_policy(request, response, csp_header_found)

            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def check_meta_policy(self, request: Request, response: Response, has_header: bool):
        csp_meta_elements = self.get_meta_policies(response.text)
        if not csp_meta_elements:
            return

        for element in csp_meta_elements:
            meta_field = element.get("http-equiv")
            meta_policy = element.get("content")
            if meta_field.lower() == "content-security-policy" and meta_policy:
                meta_observed_errors = []
                parsed_meta_policy = self.parse_policy(meta_policy, meta_observed_errors, request, response)
                if parsed_meta_policy is None:
                    continue
                self.check_observed_errors(meta_observed_errors, request, response, meta_policy, True)
                meta_wildcard_sources = self.get_allowed_wildcard_sources(meta_policy)
                meta_wildcard_sources.remove("frame-ancestors")
                self.check_wildcard_sources(meta_wildcard_sources, request, response, meta_policy, True)

                # Further checks based on parsed_meta_policy...
                if parsed_meta_policy.allows_unsafe_inline_script():
                    self.build_script_unsafe_inline_alert(meta_field, meta_policy)

                if parsed_meta_policy.allows_unsafe_inline_style():
                    self.build_style_unsafe_inline_alert(meta_field, meta_policy)

                if parsed_meta_policy.allows_unsafe_hashes("script-src"):
                    self.build_script_unsafe_hash_alert(meta_field, meta_policy)

                if parsed_meta_policy.allows_unsafe_hashes("style-src"):
                    self.build_style_unsafe_hash_alert(meta_field, meta_policy)

                if parsed_meta_policy.sandbox() or parsed_meta_policy.frame_ancestors() or parsed_meta_policy.report_uri():
                    self.build_bad_meta_alert(meta_field, meta_policy)
                if parsed_meta_policy.allows_unsafe_eval("script-src"):
                    self.build_script_unsafe_eval_alert("Content-Security-Policy", meta_policy)

            if has_header:
                self.build_both_alert()

    def check_xcsp(self, response: Response, csp_header_found: bool):
        xcsp_options = response.headers.get(self.HTTP_HEADER_XCSP)
        if xcsp_options:
            self.build_xcsp_alert(
                Risk.RISK_INFO if csp_header_found else Risk.RISK_LOW,
                self.HTTP_HEADER_XCSP,
                xcsp_options
            )

    def check_xwebkit_csp(self, response: Response, csp_header_found: bool):
        xwkcsp_options = response.headers.get(self.HTTP_HEADER_WEBKIT_CSP)
        if xwkcsp_options:
            self.build_webkit_csp_alert(
                Risk.RISK_INFO if csp_header_found else Risk.RISK_LOW,
                self.HTTP_HEADER_WEBKIT_CSP,
                xwkcsp_options
            )

    def parse_policy(self, csp: str, observed_errors: List, request: Request, response: Response):
        try:
            # Assuming Policy is some defined class with a parse_serialized_csp method
            return Policy.parse_serialized_csp(csp, observed_errors)
        except ValueError as ve:
            if "not ascii" in str(ve):
                self.build_malformed_alert(
                    self.HTTP_HEADER_WEBKIT_CSP,
                    csp,
                    self.get_nonascii_characters(csp)
                )
            else:
                logger.warning(f"CSP Found but not fully parsed, in message {request.url}.")
        return None

    def check_observed_errors(self, observed_errors: List, request: Request, response: Response, csp: str, is_meta: bool):
        csp_notices_string = self.get_csp_notices_string(observed_errors)
        if csp_notices_string:
            notices_risk = Risk.RISK_LOW if "errors" in csp_notices_string or "warnings" in csp_notices_string else Risk.RISK_INFO
            self.build_notices_alert(
                notices_risk,
                self.HTTP_HEADER_WEBKIT_CSP if is_meta else self.HTTP_HEADER_WEBKIT_CSP,
                csp,
                csp_notices_string
            )

    def check_wildcard_sources(self, allowed_wildcard_sources: List[str], request: Request, response: Response, csp: str, is_meta: bool):
        if not allowed_wildcard_sources:
            return

        allowed_directives_without_fallback = list(set(allowed_wildcard_sources).intersection(set(self.DIRECTIVES_WITHOUT_FALLBACK)))
        wildcard_src_other_info = f"Wildcard sources: {', '.join(allowed_wildcard_sources)}"
        if allowed_directives_without_fallback:
            wildcard_src_other_info += f" | Extended: {', '.join(allowed_directives_without_fallback)}"

        self.build_wildcard_alert(
            self.HTTP_HEADER_WEBKIT_CSP if is_meta else self.HTTP_HEADER_WEBKIT_CSP,
            csp,
            wildcard_src_other_info
        )

    def get_meta_policies(self, response_text: str) -> List[Dict[str, str]]:
        """
        Extracts CSP meta policies from the HTML content.

        Args:
            response_text (str): The HTML content of the response.

        Returns:
            List[Dict[str, str]]: A list of dictionaries, each representing a CSP meta policy.
        """
        soup = BeautifulSoup(response_text, 'html.parser')
        meta_elements = soup.find_all('meta', {'http-equiv': 'Content-Security-Policy'})

        meta_policies = []
        for meta in meta_elements:
            meta_policies.append({
                'http-equiv': meta.get('http-equiv', ''),
                'content': meta.get('content', '')
            })

        return meta_policies

    def build_xcsp_alert(self, risk, param, evidence):
        return Alert(
            risk_category=risk,
            confidence=self.CONFIDENCE,
            description="X-Content-Security-Policy detected",
            msg_ref=self.MSG_REF + ".xcsp",
            evidence=evidence,
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id()
        )

    def build_webkit_csp_alert(self, risk, param, evidence):
        return Alert(
            risk_category=risk,
            confidence=self.CONFIDENCE,
            description="X-WebKit-CSP detected",
            msg_ref=self.MSG_REF + ".xwkcsp",
            evidence=evidence,
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id()
        )

    def build_malformed_alert(self, param, evidence, bad_chars):
        return Alert(
            risk_category=self.RISK,
            confidence=self.CONFIDENCE,
            description="Malformed Content-Security-Policy",
            msg_ref=self.MSG_REF + ".malformed",
            evidence=evidence,
            other_info=f"Non-ASCII characters: {bad_chars}",
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id()
        )

    def build_notices_alert(self, risk, param, evidence, otherinfo):
        return Alert(
            risk_category=risk,
            confidence=self.CONFIDENCE,
            description="CSP Notices",
            msg_ref=self.MSG_REF + ".notices",
            evidence=evidence,
            other_info=otherinfo,
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id()
        )

    def build_wildcard_alert(self, param, evidence, otherinfo):
        return Alert(
            risk_category=self.RISK,
            confidence=self.CONFIDENCE,
            description="CSP Wildcard Sources",
            msg_ref=self.MSG_REF + ".wildcard",
            evidence=evidence + otherinfo,
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id()
        )

    def build_script_unsafe_inline_alert(self, param, evidence):
        return Alert(
            risk_category=self.RISK,
            confidence=self.CONFIDENCE,
            description="Unsafe Inline Script",
            msg_ref=self.MSG_REF + ".scriptsrc.unsafe",
            evidence=evidence,
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id()
        )

    def build_style_unsafe_inline_alert(self, param, evidence):
        return Alert(
            risk_category=self.RISK,
            confidence=self.CONFIDENCE,
            description="Unsafe Inline Style",
            msg_ref=self.MSG_REF + ".stylesrc.unsafe",
            evidence=evidence,
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id()
        )

    def build_script_unsafe_hash_alert(self, param, evidence):
        return Alert(
            risk_category=self.RISK,
            confidence=self.CONFIDENCE,
            description="Unsafe Hash in Script",
            msg_ref=self.MSG_REF + ".scriptsrc.unsafe.hashes",
            evidence=evidence,
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id()
        )

    def build_style_unsafe_hash_alert(self, param, evidence):
        return Alert(
            risk_category=self.RISK,
            confidence=self.CONFIDENCE,
            description="Unsafe Hash in Style",
            msg_ref=self.MSG_REF + ".stylesrc.unsafe.hashes",
            evidence=evidence,
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id()
        )

    def build_script_unsafe_eval_alert(self, param, evidence):
        return Alert(
            risk_category=self.RISK,
            confidence=self.CONFIDENCE,
            description="Unsafe Eval in Script",
            msg_ref=self.MSG_REF + ".scriptsrc.unsafe.eval",
            evidence=evidence,
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id()
        )

    def build_bad_meta_alert(self, param, evidence):
        return Alert(
            risk_category=self.RISK,
            confidence=self.CONFIDENCE,
            description="Bad Directive in Meta Tag",
            msg_ref=self.MSG_REF + ".meta.bad.directive",
            evidence=evidence,
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id()
        )

    def build_both_alert(self):
        return Alert(
            risk_category=Risk.RISK_INFO,
            confidence=self.CONFIDENCE,
            description="Both CSP Header and Meta Tag",
            msg_ref=self.MSG_REF + ".both",
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id()
        )

    def has_meta_csp(self, response_text: str) -> bool:
        # Placeholder for checking meta CSP
        return "Content-Security-Policy" in response_text

    def get_nonascii_characters(self, csp: str) -> str:
        return "".join([char for char in csp if ord(char) > 127])

    def get_csp_notices_string(self, notices: List) -> str:
        if not notices:
            return ""
        return "\n".join([notice.message for notice in notices])

    def __str__(self) -> str:
        return "Content Security Policy Scan Rule"

    def get_cwe_id(self) -> int:
        return 693  # CWE-693: Protection Mechanism Failure

    def get_wasc_id(self) -> int:
        return 15  # WASC-15: Application Misconfiguration



class Policy:
    def __init__(self, directives: Dict[str, List[str]]):
        self.directives = directives

    def allows_unsafe_inline_script(self) -> bool:
        return self._allows_unsafe('script-src', "'unsafe-inline'")

    def allows_unsafe_inline_style(self) -> bool:
        return self._allows_unsafe('style-src', "'unsafe-inline'")

    def allows_unsafe_hashes(self, directive: str) -> bool:
        return self._allows_unsafe(directive, "'unsafe-hashes'")

    def allows_unsafe_eval(self, directive: str) -> bool:
        return self._allows_unsafe(directive, "'unsafe-eval'")

    def _allows_unsafe(self, directive: str, unsafe_value: str) -> bool:
        return unsafe_value in self.directives.get(directive, [])

    @staticmethod
    def parse_serialized_csp(csp: str, observed_errors: List) -> 'Policy':
        directives = {}
        try:
            for directive in csp.split(';'):
                if not directive.strip():
                    continue
                parts = directive.strip().split(None, 1)
                if len(parts) == 1:
                    directives[parts[0]] = []
                else:
                    directives[parts[0]] = parts[1].split()
        except Exception as e:
            observed_errors.append(f"Failed to parse CSP: {str(e)}")
            return None
        return Policy(directives)