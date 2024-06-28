import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError

logger = logging.getLogger(__name__)

class CacheControlScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for proper Cache-Control headers.
    """
    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for proper Cache-Control headers in the HTTP response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            # Check if the request is secure and response body is not empty
            if request.url.startswith('https') and len(response.content) > 0:
                # Exclude images, JavaScript, and CSS
                content_type = response.headers.get("Content-Type", "").lower()
                if any(ctype in content_type for ctype in ["image/", "javascript", "css"]):
                    return NoAlert()

                # Get Cache-Control headers
                cache_control_headers = response.headers.get("Cache-Control", "").lower()

                # Check if Cache-Control headers are missing or improperly configured
                if not cache_control_headers or \
                   "no-store" not in cache_control_headers or \
                   "no-cache" not in cache_control_headers or \
                   "must-revalidate" not in cache_control_headers:
                    return Alert(
                        risk_category="Information",
                        description="Improper or missing Cache-Control headers",
                        msg_ref="pscanrules.cachecontrol.missing_or_improper",
                        cwe_id=self.get_cwe_id(),
                        wasc_id=self.get_wasc_id(),
                        evidence=cache_control_headers
                    )
            
            return NoAlert()
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e))
        
    def __str__(self) -> str:
        """
        Returns a string representation of the CacheControlScanRule object.

        Returns:
            str: A string representation of the CacheControlScanRule object.
        """
        return "Cache-Control Header"
    
    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 525 # CWE-525: Use of Web Browser Cache Containing Sensitive Information

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 13 # WASC-13: Information Leakage
