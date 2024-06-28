import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.risk import Risk
from .utils.confidence import Confidence

logger = logging.getLogger(__name__)

class XDebugTokenScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for X-Debug-Token and X-Debug-Token-Link headers.
    """

    MSG_REF = "pscanrules.xdebugtoken"

    X_DEBUG_TOKEN_HEADER = "X-Debug-Token"
    X_DEBUG_TOKEN_LINK_HEADER = "X-Debug-Token-Link"

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for X-Debug-Token and X-Debug-Token-Link headers in the HTTP response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        
        try:
            # Check for X-Debug-Token-Link header
            if self.response_has_header(response, self.X_DEBUG_TOKEN_LINK_HEADER):
                return self.build_alert(response.headers.get(self.X_DEBUG_TOKEN_LINK_HEADER))
            
            # Check for X-Debug-Token header
            if self.response_has_header(response, self.X_DEBUG_TOKEN_HEADER):
                return self.build_alert(response.headers.get(self.X_DEBUG_TOKEN_HEADER))
            
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def build_alert(self, evidence: str) -> Alert:
        """
        Build an Alert object with the given evidence.

        Args:
            evidence (str): The evidence string.

        Returns:
            Alert: An Alert object.
        """
        return Alert(
            risk_category=Risk.RISK_LOW,
            description="X-Debug-Token Information Leak",
            confidence=Confidence.CONFIDENCE_HIGH,
            msg_ref=self.MSG_REF,
            evidence=evidence,
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id()
        )

    def response_has_header(self, response: Response, header: str) -> bool:
        """
        Check if the response contains the specified header.

        Args:
            response (Response): The HTTP response object.
            header (str): The header name to check.

        Returns:
            bool: True if the header is present, False otherwise.
        """
        return header in response.headers

    def __str__(self) -> str:
        """
        Returns a string representation of the XDebugTokenScanRule object.

        Returns:
            str: A string representation of the XDebugTokenScanRule object.
        """
        return "X-Debug-Token Header"

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 200 # CWE-200: Information Exposure

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 13 # WASC-13: Info leakage
