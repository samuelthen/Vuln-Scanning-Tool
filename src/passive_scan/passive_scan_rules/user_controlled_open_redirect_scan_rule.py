import logging
from requests.models import Request, Response
from urllib.parse import urlparse, urljoin
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class UserControlledOpenRedirectScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for user-controlled open redirects.
    """
    MSG_REF = "pscanrules.usercontrolledopenredirect"
    RISK = Risk.RISK_HIGH
    CONFIDENCE = Confidence.CONFIDENCE_MEDIUM

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A03_INJECTION,
        CommonAlertTag.OWASP_2017_A01_INJECTION,
        CommonAlertTag.WSTG_V42_CLNT_04_OPEN_REDIR
    ]

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for user-controlled open redirects in HTTP responses.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            if response.status_code in [301, 302]:
                location = response.headers.get('Location')
                if location:
                    params = {**request.params, **request.data}
                    if self.is_user_controlled_redirect(location, params):
                        return Alert(risk_category=self.RISK,
                                     confidence=self.CONFIDENCE,
                                     description="User-controlled open redirect detected",
                                     msg_ref=self.MSG_REF,
                                     evidence=location,
                                     cwe_id=self.get_cwe_id(),
                                     wasc_id=self.get_wasc_id())
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def is_user_controlled_redirect(self, location: str, params: dict) -> bool:
        """
        Check if the redirect location is controlled by user input.

        Args:
            location (str): The redirect location.
            params (dict): The parameters from the request.

        Returns:
            bool: True if the redirect is user-controlled, False otherwise.
        """
        parsed_location = urlparse(location)
        if parsed_location.netloc:
            for param, value in params.items():
                if value and (value in location or value == parsed_location.netloc):
                    return True
        return False

    def __str__(self) -> str:
        """
        Returns a string representation of the UserControlledOpenRedirectScanRule object.

        Returns:
            str: A string representation of the UserControlledOpenRedirectScanRule object.
        """
        return "User-Controlled Open Redirect"

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 601  # CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 38  # WASC-38: URL Redirector Abuse
