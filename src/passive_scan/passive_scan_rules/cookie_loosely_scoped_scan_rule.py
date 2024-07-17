import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class CookieLooselyScopedScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for loosely scoped cookies.
    """
    MSG_REF = "pscanrules.cookielooselyscoped"
    RISK = Risk.RISK_INFO
    CONFIDENCE = Confidence.CONFIDENCE_LOW

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A08_INTEGRITY_FAIL,
        CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
        CommonAlertTag.WSTG_V42_SESS_02_COOKIE_ATTRS
    ]
    
    def check_risk(self, request: Request, response: Response) -> Alert:
        try:
            host = request.url.split("//")[1].split("/")[0]
            cookies = response.headers.get('Set-Cookie')
            
            if cookies:
                loosely_scoped_cookies = []
                for cookie in cookies.split(','):
                    cookie_parts = cookie.split(';')
                    try:
                        domain = self._get_domain_from_cookie_parts(cookie_parts)
                        if domain and self.is_loosely_scoped_cookie(domain, host):
                            loosely_scoped_cookies.append(cookie)
                    except IndexError:
                        # Handle malformed cookies
                        continue
                
                if loosely_scoped_cookies:
                    return Alert(risk_category=self.RISK,
                                confidence=self.CONFIDENCE,
                                description="Loosely scoped cookies detected",
                                msg_ref=self.MSG_REF,
                                evidence=", ".join(loosely_scoped_cookies),
                                cwe_id=self.get_cwe_id(), 
                                wasc_id=self.get_wasc_id())
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    
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
        # Preconditions
        if not cookie_domain or not host:
            return False

        # If Domain attribute hasn't been specified, the cookie is scoped with the response host
        if not cookie_domain:
            return False

        # Split cookie domain into sub-domains
        cookie_domains = cookie_domain.split('.')
        # Split host FQDN into sub-domains
        host_domains = host.split('.')

        # Check if the cookie and host belong to the same domain
        is_from_the_same_domain = self.is_cookie_and_host_have_the_same_domain(cookie_domains, host_domains)
        if not is_from_the_same_domain:
            return True

        # If cookie domain doesn't start with '.', and the domain is not a second-level domain (example.com),
        # the cookie Domain and host values should match exactly
        if not cookie_domain.startswith('.') and len(cookie_domains) >= 2 and not is_from_the_same_domain:
            return cookie_domain != host

        # Remove leading '.' if present and split again
        if cookie_domain.startswith('.'):
            cookie_domains = cookie_domain.lstrip('.').split('.')

        # Loosely scoped domain name should have fewer sub-domains
        if len(cookie_domains) == 0 or len(cookie_domains) >= len(host_domains):
            return False

        # Those sub-domains should match the right most sub-domains of the origin domain name
        for i in range(1, len(cookie_domains) + 1):
            if cookie_domains[-i].lower() != host_domains[-i].lower():
                return False

        # Right-most domains matched, the cookie is loosely scoped
        return True

    def is_cookie_and_host_have_the_same_domain(self, cookie_domains, host_domains):
        """
        Check if cookie and host have the same domain.
        
        Args:
            cookie_domains (list): The list of sub-domains in the cookie domain.
            host_domains (list): The list of sub-domains in the host domain.

        Returns:
            bool: True if they have the same domain, otherwise False.
        """
        if not cookie_domains or not host_domains or cookie_domains[0].lower() == "null" or host_domains[0].lower() == "null":
            return True

        if cookie_domains[-1].lower() != host_domains[-1].lower():
            return False

        if len(cookie_domains) < 2 or len(host_domains) < 2 or cookie_domains[-2].lower() != host_domains[-2].lower():
            return False

        return True

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
