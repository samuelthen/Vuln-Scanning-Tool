import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError

logger = logging.getLogger(__name__)

class AntiClickjackingScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for anti-clickjacking protection headers.
    """
    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for anti-clickjacking protection headers.

        Returns:
        - 
        """
        try:
            # Check if the response is HTML
            if "Content-Type" in response.headers and "text/html" in response.headers["Content-Type"]:
                # Check for Content-Security-Policy header
                if "Content-Security-Policy" in response.headers:
                    csp_values = response.headers.get("Content-Security-Policy").lower()
                    if "frame-ancestors" in csp_values:
                        return NoAlert()
                
                # Check for X-Frame-Options header
                if "X-Frame-Options" in response.headers:
                    xfo_values = response.headers.get("X-Frame-Options").lower()
                    if "deny" not in xfo_values and "sameorigin" not in xfo_values:
                        return Alert(risk_category="Medium", 
                                     description="X-Frame-Options not properly set", 
                                     msg_ref="pscanrules.anticlickjacking.compliance.malformed.setting",
                                     cwe_id=self.get_cwe_id(), 
                                     wasc_id=self.get_wasc_id())
                    if len(xfo_values) > 1:
                        return Alert(risk_category="Medium", 
                                     description="Multiple X-Frame-Options headers",
                                     msg_ref="pscanrules.anticlickjacking.multiple.header",
                                     cwe_id=self.get_cwe_id(), 
                                     wasc_id=self.get_wasc_id())
                else:
                    return Alert(risk_category="Medium", 
                                 description="X-Frame-Options header missing",
                                 msg_ref="pscanrules.anticlickjacking.missing",
                                 cwe_id=self.get_cwe_id(), 
                                 wasc_id=self.get_wasc_id())
            
            return NoAlert()
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logging.error(f"Error during scan: {e}")
            return ScanError(description=e)
        
    def __str__(self) -> str:
        return "Anti-clickjacking Header"
    
    def get_cwe_id(self):
        return 1021 # CWE-1021: Improper Restriction of Rendered UI Layers or Frames

    def get_wasc_id(self):
        return 15 # WASC-15: Application Misconfiguration