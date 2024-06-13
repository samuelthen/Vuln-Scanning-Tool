import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from http.cookies import SimpleCookie

logger = logging.getLogger(__name__)

class CookieHttpOnlyScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for the HttpOnly attribute in cookies.
    """

    HTTP_ONLY_COOKIE_ATTRIBUTE = "HttpOnly"

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for the HttpOnly attribute in cookies.

        Returns:
        - Alert
        """
        try:
            cookies1 = response.headers.get('Set-Cookie', [])
            cookies2 = response.headers.get('Set-Cookie2', [])
            cookies = cookies1 + cookies2

            ignore_list = self.get_cookie_ignore_list()

            for header_value in cookies:
                if not self.has_attribute(header_value, self.HTTP_ONLY_COOKIE_ATTRIBUTE):
                    if self.is_expired(header_value):
                        continue
                    if self.get_cookie_name(header_value) not in ignore_list:
                        return Alert(risk_category="Low",
                                     description="Cookie does not have HttpOnly flag",
                                     msg_ref="pscanrules.cookiehttponly",
                                     evidence=header_value,
                                     cwe_id=self.get_cwe_id(),
                                     wasc_id=self.get_wasc_id())
            return NoAlert()
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e))
    
    def is_expired(self, header_value: str) -> bool:
        # Check if the cookie is expired
        cookie = SimpleCookie(header_value)
        for key, morsel in cookie.items():
            expires = morsel.get('expires')
            if expires:
                # Simple expiration check (you may need to handle different formats)
                from datetime import datetime
                try:
                    expire_time = datetime.strptime(expires, "%a, %d-%b-%Y %H:%M:%S %Z")
                    if expire_time < datetime.utcnow():
                        return True
                except ValueError:
                    pass
        return False
    
    def get_cookie_ignore_list(self):
        # Implement a method to return the list of cookies to be ignored
        return set()

    def has_attribute(self, header_value: str, attribute: str) -> bool:
        # Check if the cookie has the specified attribute
        cookie = SimpleCookie(header_value)
        for key, morsel in cookie.items():
            if attribute.lower() in morsel.get('httponly', '').lower():
                return True
        return False
    
    def get_cookie_name(self, header_value: str) -> str:
        # Extract the cookie name
        cookie = SimpleCookie(header_value)
        for key in cookie.keys():
            return key
        return ""
    
    def __str__(self) -> str:
        return "Cookie HttpOnly Flag"

    def get_cwe_id(self):
        return 1004  # CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag

    def get_wasc_id(self):
        return 13  # WASC-13: Info leakage

    

