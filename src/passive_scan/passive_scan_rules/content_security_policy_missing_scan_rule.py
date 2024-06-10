from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule

class ContentSecurityPolicyMissingScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for missing Content-Security-Policy headers or obsolete CSP headers.
    """
    def check_risk(self, request: Request, response: Response) -> str:
        """
        Check for missing Content-Security-Policy headers or obsolete CSP headers.

        Returns:
        - str: A message indicating the risk level.
        """
        try:
            # Check if the response is HTML
            if "Content-Type" in response.headers and "text/html" in response.headers["Content-Type"]:
                # Check if CSP header is present
                if "Content-Security-Policy" in response.headers:
                    csp_values = response.headers.get("Content-Security-Policy").lower()
                    if "frame-ancestors" in csp_values:
                        return "Low risk (protected by Content-Security-Policy)"
                
                # Check for obsolete CSP headers
                if "X-Content-Security-Policy" in response.headers or \
                "X-WebKit-CSP" in response.headers:
                    return "Low risk (obsolete CSP header present)"

                # Check for CSP report-only header
                if "Content-Security-Policy-Report-Only" in response.headers:
                    return "Low risk (CSP report-only header present)"
                
                # If no CSP headers are present
                return "Medium risk (Content-Security-Policy header missing)"
            
            return "No risk (not an HTML response)"
        except Exception as e:
            # Handle any exceptions that occur during the scan
            print(f"Error during scan: {e}")
            return 'Error occurred during scan, check logs for details'
        
    def __str__(self) -> str:
        return "Content Security Policy (CSP) Header"
