import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class XAspNetVersionScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for the presence of the X-AspNet-Version/X-AspNetMvc-Version response header.
    """

    MSG_REF = "pscanrules.xaspnetversion"
    RISK = Risk.RISK_LOW
    CONFIDENCE = Confidence.CONFIDENCE_HIGH

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
        CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
        CommonAlertTag.WSTG_V42_INFO_08_FINGERPRINT_APP_FRAMEWORK
    ]

    def __init__(self):
        """
        Initialize the scan rule with the headers to check.
        """
        self.x_asp_net_headers = ["X-AspNet-Version", "X-AspNetMvc-Version"]

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for the presence of the X-AspNet-Version/X-AspNetMvc-Version headers in the HTTP response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            for header in self.x_asp_net_headers:
                if header in response.headers:
                    evidence = response.headers.get(header)
                    return Alert(
                        risk_category=self.RISK,
                        confidence=self.CONFIDENCE,
                        description="ASP.NET version information disclosure",
                        msg_ref=self.MSG_REF,
                        cwe_id=self.get_cwe_id(), 
                        wasc_id=self.get_wasc_id(),
                        evidence=evidence
                    )

            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def __str__(self) -> str:
        """
        Returns a string representation of the XAspNetVersionScanRule object.

        Returns:
            str: A string representation of the XAspNetVersionScanRule object.
        """
        return "ASP.NET Version Header"

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 933  # CWE-933: OWASP Top Ten 2013 Category A5 - Security Misconfiguration

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 14  # WASC-14: Server Misconfiguration
