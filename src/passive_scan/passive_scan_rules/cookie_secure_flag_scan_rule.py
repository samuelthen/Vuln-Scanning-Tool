import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError

logger = logging.getLogger(__name__)

class CookieSecureFlagScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for the Secure attribute in cookies.
    """
    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for the Secure attribute in cookies.

        Returns:
        - Alert
        """
        try:
            # Check if the response is over a secure channel
            if request.url.startswith("https://"):
                cookies = response.headers.get('Set-Cookie')
                if cookies:
                    if 'Secure' not in cookies:
                        return Alert(risk_category="Low", 
                                     description="missing Secure attribute in cookie",
                                     msg_ref="pscanrules.cookiesecureflag",
                                     evidence=cookies,
                                     cwe_id=self.get_cwe_id(), 
                                     wasc_id=self.get_wasc_id())
                return NoAlert()
            return NoAlert()
        except Exception as e: 
            # Handle any exceptions that occur during the scan
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e))

    def __str__(self) -> str:
        return "Cookie Secure Flag"

    def get_cwe_id(self):
        return 614 # CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

    def get_wasc_id(self):
        return 13 # WASC-13: Info leakage
