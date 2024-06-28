import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class ContentTypeMissingScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for missing or empty Content-Type headers.
    """
    MSG_REF = "pscanrules.contenttypemissing"
    RISK = Risk.RISK_INFO
    CONFIDENCE = Confidence.CONFIDENCE_MEDIUM

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
        CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG
    ]

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for missing or empty Content-Type headers in the HTTP response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            # Check if the response body has content
            if response.content:
                # Retrieve the Content-Type header
                content_type = response.headers.get("Content-Type", None)
                if content_type is None:
                    # Content-Type header is missing
                    return Alert(risk_category=self.RISK,
                                 confidence=self.CONFIDENCE,
                                 description="Content-Type header is missing",
                                 msg_ref=self.MSG_REF,
                                 cwe_id=self.get_cwe_id(),
                                 wasc_id=self.get_wasc_id())
                elif not content_type.strip():
                    # Content-Type header is empty
                    return Alert(risk_category=self.RISK,
                                 confidence=self.CONFIDENCE,
                                 description="Content-Type header is empty",
                                 msg_ref=self.MSG_REF,
                                 cwe_id=self.get_cwe_id(),
                                 wasc_id=self.get_wasc_id())
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e),msg_ref=self.MSG_REF)
        
    def __str__(self) -> str:
        """
        Returns a string representation of the ContentTypeMissingScanRule object.

        Returns:
            str: A string representation of the ContentTypeMissingScanRule object.
        """
        return "Content-Type Missing or Empty Header"
    
    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 345 # CWE-345: Insufficient Verification of Data Authenticity

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 12 # WASC-12: Content Spoofing
