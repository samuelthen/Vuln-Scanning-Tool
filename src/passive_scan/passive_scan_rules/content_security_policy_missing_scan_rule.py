import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.csp_utils import CspUtils

logger = logging.getLogger(__name__)

class ContentSecurityPolicyMissingScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for missing Content-Security-Policy headers or obsolete CSP headers.
    """
    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for missing Content-Security-Policy headers or obsolete CSP headers.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            # Check if the response is HTML
            if "Content-Type" in response.headers and "text/html" in response.headers["Content-Type"]:
                # Check if CSP header is present
                if "Content-Security-Policy" not in response.headers:
                    if not CspUtils.has_meta_csp(response.text):
                        return Alert(risk_category="Medium", 
                                     description="Content-Security-Policy header missing",
                                     msg_ref="pscanrules.contentsecuritypolicymissing",
                                     cwe_id=self.get_cwe_id(), 
                                     wasc_id=self.get_wasc_id())
                
                # Check for obsolete CSP headers
                if "X-Content-Security-Policy" in response.headers or \
                "X-WebKit-CSP" in response.headers:
                    return Alert(risk_category="Informational", 
                                 description="Obsolete CSP header present",
                                 msg_ref="pscanrules.contentsecuritypolicymissing.obs")

                # Check for CSP report-only header
                if "Content-Security-Policy-Report-Only" in response.headers:
                    return Alert(risk_category="Informational", 
                                 description="CSP report-only header present",
                                 msg_ref="pscanrules.contentsecuritypolicymissing.ro")
            
            return NoAlert()
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e))
        
    def __str__(self) -> str:
        """
        Returns a string representation of the ContentSecurityPolicyMissingScanRule object.

        Returns:
            str: A string representation of the ContentSecurityPolicyMissingScanRule object.
        """
        return "Content Security Policy (CSP) Header"
    
    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 693 # CWE-693: Protection Mechanism Failure

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 15 # WASC-15: Application Misconfiguration