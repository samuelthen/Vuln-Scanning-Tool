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
                        return Alert(risk_category="Low", 
                                     description="Missing Secure attribute in cookie",
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

