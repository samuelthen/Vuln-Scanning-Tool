from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule

class AntiClickjackingScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for anti-clickjacking protection headers.
    """
    def check_risk(self, request: Request, response: Response) -> str:
        """
        Check for anti-clickjacking protection headers.

        Returns:
        - Alert
        """
        try:
            # Check if the response is HTML
            if "Content-Type" in response.headers and "text/html" in response.headers["Content-Type"]:
                # Check for Content-Security-Policy header
                if "Content-Security-Policy" in response.headers:
                    if "frame-ancestors" in response.headers["Content-Security-Policy"]:
                        return "Low risk (protected by Content-Security-Policy)"
                
                # Check for X-Frame-Options header
                if "X-Frame-Options" in response.headers:
                    xfo_values = response.headers.get("X-Frame-Options").lower()
                    if "deny" not in xfo_values and "sameorigin" not in xfo_values:
                        return "Medium risk (X-Frame-Options not properly set)"
                    else:
                        return "Low risk (protected by X-Frame-Options)"
                else:
                    return "High risk (X-Frame-Options header missing)"
            
            return "No risk (not an HTML response)"
        except Exception as e:
            # Handle any exceptions that occur during the scan
            print(f"Error during scan: {e}")
            return 'Error occurred during scan, check logs for details'
        
    def __str__(self) -> str:
        return "Anti-clickjacking Header"