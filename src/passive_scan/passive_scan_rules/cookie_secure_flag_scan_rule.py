import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class CookieSecureFlagScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for the Secure attribute in cookies.
    """
    MSG_REF = "pscanrules.cookiesecureflag"
    RISK = Risk.RISK_LOW
    CONFIDENCE = Confidence.CONFIDENCE_MEDIUM

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
        CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
        CommonAlertTag.WSTG_V42_SESS_02_COOKIE_ATTRS
    ]

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for the Secure attribute in cookies.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            # Check if the response is over a secure channel
            if request.url.startswith("https://"):
                cookies = response.headers.get('Set-Cookie')
                if cookies:
                    # Check if the Secure attribute is present in the cookies
                    if 'Secure' not in cookies:
                        return Alert(risk_category=self.RISK,
                                     confidence=self.CONFIDENCE, 
                                     description="Missing Secure attribute in cookie",
                                     msg_ref=self.MSG_REF,
                                     evidence=cookies,
                                     cwe_id=self.get_cwe_id(), 
                                     wasc_id=self.get_wasc_id())
                return NoAlert(msg_ref=self.MSG_REF)
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def __str__(self) -> str:
        """
        Returns a string representation of the CookieSecureFlagScanRule object.

        Returns:
            str: A string representation of the CookieSecureFlagScanRule object.
        """
        return "Cookie Secure Flag"

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 614 # CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 13 # WASC-13: Info leakage

