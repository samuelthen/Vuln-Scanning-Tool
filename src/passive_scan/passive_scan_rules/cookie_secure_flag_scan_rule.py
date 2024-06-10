from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule

class CookieSecureFlagScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for the Secure attribute in cookies.
    """
    def check_risk(self, request: Request, response: Response) -> str:
        """
        Check for the Secure attribute in cookies.

        Returns:
        - str: A message indicating the risk level.
        """
        try:
            # Check if the response is over a secure channel
            if request.url.startswith("https://"):
                cookies = response.headers.get('Set-Cookie')
                if cookies:
                    if 'Secure' not in cookies:
                        return 'Low risk (missing Secure attribute in cookie)'
                return 'No risk (cookies secure)'
            return 'No risk (not an HTTPS response)'
        except Exception as e:
            # Handle any exceptions that occur during the scan
            print(f"Error during scan: {e}")
            return 'Error occurred during scan, check logs for details'

    def __str__(self) -> str:
        return "Cookie Secure Flag"
