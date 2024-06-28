import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class XContentTypeOptionsScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for X-Content-Type-Options header.
    """
    MSG_REF = "pscanrules.xcontenttypeoptions"
    RISK = Risk.RISK_LOW
    CONFIDENCE = Confidence.CONFIDENCE_MEDIUM

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
        CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG
    ]

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for X-Content-Type-Options header in the HTTP response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            # Check if the response has a body
            if response.content:
                # Get the X-Content-Type-Options headers
                x_content_type_options = response.headers.get("X-Content-Type-Options", None)
                if not x_content_type_options:
                    return Alert(
                        risk_category=self.RISK,
                        confidence=self.CONFIDENCE,
                        description="X-Content-Type-Options header missing",
                        msg_ref=self.MSG_REF,
                        cwe_id=self.get_cwe_id(),
                        wasc_id=self.get_wasc_id()
                    )
                elif "nosniff" not in x_content_type_options.lower():
                    return Alert(
                        risk_category=self.RISK,
                        confidence=self.CONFIDENCE,
                        description="X-Content-Type-Options header set incorrectly",
                        msg_ref=self.MSG_REF,
                        cwe_id=self.get_cwe_id(),
                        wasc_id=self.get_wasc_id(),
                        evidence=x_content_type_options
                    )

            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def __str__(self) -> str:
        """
        Returns a string representation of the XContentTypeOptionsScanRule object.

        Returns:
            str: A string representation of the XContentTypeOptionsScanRule object.
        """
        return "X-Content-Type-Options Header"

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 693  # CWE-693: Protection Mechanism Failure

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 15  # WASC-15: Application Misconfiguration
