import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class AntiClickjackingScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for anti-clickjacking protection headers.
    """
    MSG_REF = "pscanrules.anticlickjacking"
    RISK = Risk.RISK_MEDIUM
    CONFIDENCE = Confidence.CONFIDENCE_MEDIUM

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
        CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
        CommonAlertTag.WSTG_V42_CLNT_09_CLICKJACK
    ]

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for anti-clickjacking protection headers in the HTTP response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            # Check if the response is HTML
            if "Content-Type" in response.headers and "text/html" in response.headers["Content-Type"]:
                # Check for Content-Security-Policy header
                included_in_csp = False
                if "Content-Security-Policy" in response.headers:
                    csp_values = response.headers.get("Content-Security-Policy").lower()
                    if "frame-ancestors" in csp_values:
                        included_in_csp = True
                
                # Check for X-Frame-Options header
                if "X-Frame-Options" in response.headers:
                    xfo_values = response.headers.get("X-Frame-Options").lower()
                    # Check for proper X-Frame-Options values
                    if "deny" not in xfo_values and "sameorigin" not in xfo_values:
                        return Alert(risk_category=self.RISK if not included_in_csp else Risk.RISK_LOW,
                                     confidence=self.CONFIDENCE, 
                                     description="X-Frame-Options not properly set", 
                                     msg_ref="pscanrules.anticlickjacking.compliance.malformed.setting",
                                     cwe_id=self.get_cwe_id(), 
                                     wasc_id=self.get_wasc_id())
                    # Check for multiple X-Frame-Options headers
                    if len(xfo_values) > 1:
                        return Alert(risk_category=self.RISK if not included_in_csp else Risk.RISK_LOW,
                                     confidence=self.CONFIDENCE, 
                                     description="Multiple X-Frame-Options headers",
                                     msg_ref="pscanrules.anticlickjacking.multiple.header",
                                     cwe_id=self.get_cwe_id(), 
                                     wasc_id=self.get_wasc_id())
                else:
                    # X-Frame-Options header is missing
                    return Alert(risk_category=self.RISK if not included_in_csp else Risk.RISK_LOW,
                                 confidence=self.CONFIDENCE, 
                                 description="X-Frame-Options header missing",
                                 msg_ref="pscanrules.anticlickjacking.missing",
                                 cwe_id=self.get_cwe_id(), 
                                 wasc_id=self.get_wasc_id())
            
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)
        
    def __str__(self) -> str:
        """
        Returns a string representation of the AntiClickjackingScanRule object.

        Returns:
            str: A string representation of the AntiClickjackingScanRule object.
        """
        return "Anti-clickjacking Header"
    
    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 1021 # CWE-1021: Improper Restriction of Rendered UI Layers or Frames

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 15 # WASC-15: Application Misconfiguration