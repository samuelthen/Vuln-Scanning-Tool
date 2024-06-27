import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError

logger = logging.getLogger(__name__)

class CookieLooselyScopedScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for loosely scoped cookies.
    """
    
    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for loosely scoped cookies in the response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            host = request.url.split("//")[1].split("/")[0]
            cookies = response.headers.get('Set-Cookie')
            
            if cookies:
                loosely_scoped_cookies = []
                for cookie in cookies.split(','):
                    cookie_parts = cookie.split(';')
                    domain = self._get_domain_from_cookie_parts(cookie_parts)
                    if domain and self.is_loosely_scoped_cookie(domain, host):
                        loosely_scoped_cookies.append(cookie)
                
                if loosely_scoped_cookies:
                    return Alert(risk_category="Info",
                                 description="Loosely scoped cookies detected",
                                 msg_ref="pscanrules.cookielooselyscoped",
                                 evidence=", ".join(loosely_scoped_cookies),
                                 cwe_id=self.get_cwe_id(), 
                                 wasc_id=self.get_wasc_id())
            return NoAlert()
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e))
    
    def _get_domain_from_cookie_parts(self, cookie_parts):
        for part in cookie_parts:
            if 'domain' in part.lower():
                return part.split('=')[1].strip()
        return None

    def is_loosely_scoped_cookie(self, cookie_domain: str, host: str) -> bool:
        """
        Determines whether the specified cookie is loosely scoped by
        checking its Domain attribute value against the host.

        Args:
            cookie_domain (str): The domain attribute of the cookie.
            host (str): The host from which the response was sent.

        Returns:
            bool: True if the cookie is loosely scoped, otherwise False.
        """
        if not cookie_domain or cookie_domain.startswith('.'):
            cookie_domain = cookie_domain.lstrip('.')

        cookie_domains = cookie_domain.split('.')
        host_domains = host.split('.')
        
        if len(cookie_domains) < 2 or len(host_domains) < 2:
            return False
        
        for i in range(1, min(len(cookie_domains), len(host_domains)) + 1):
            if cookie_domains[-i].lower() != host_domains[-i].lower():
                return False
        
        return len(cookie_domains) < len(host_domains)

    def __str__(self) -> str:
        """
        Returns a string representation of the CookieLooselyScopedScanRule object.

        Returns:
            str: A string representation of the CookieLooselyScopedScanRule object.
        """
        return "Cookie Loosely Scoped"

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 565 # CWE-565: Reliance on Cookies without Validation and Integrity

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 15 # WASC-15: Application Misconfiguration
