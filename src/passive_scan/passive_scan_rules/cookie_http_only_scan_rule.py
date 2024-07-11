import logging
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from http.cookies import SimpleCookie
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class CookieHttpOnlyScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for the HttpOnly attribute in cookies.
    """
    MSG_REF = "pscanrules.cookiehttponly"
    RISK = Risk.RISK_LOW
    CONFIDENCE = Confidence.CONFIDENCE_MEDIUM

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
        CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
        CommonAlertTag.WSTG_V42_SESS_02_COOKIE_ATTRS
]

    HTTP_ONLY_COOKIE_ATTRIBUTE = "HttpOnly"

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for the HttpOnly attribute in cookies.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            # Retrieve cookies from response headers
            cookies1 = response.headers.get('Set-Cookie', [])
            cookies2 = response.headers.get('Set-Cookie2', [])
            
            # Ensure cookies1 and cookies2 are lists
            if not isinstance(cookies1, list):
                cookies1 = [cookies1]
            if not isinstance(cookies2, list):
                cookies2 = [cookies2]
                
            cookies = cookies1 + cookies2

            ignore_list = self.get_cookie_ignore_list()

            # Check each cookie for the HttpOnly attribute
            for header_value in cookies:
                if not self.has_attribute(header_value, self.HTTP_ONLY_COOKIE_ATTRIBUTE):
                    if self.is_expired(header_value):
                        continue
                    if self.get_cookie_name(header_value) not in ignore_list:
                        return Alert(risk_category=self.RISK,
                                     confidence=self.CONFIDENCE,
                                     description="Cookie does not have HttpOnly flag",
                                     msg_ref=self.MSG_REF,
                                     evidence=header_value,
                                     cwe_id=self.get_cwe_id(),
                                     wasc_id=self.get_wasc_id())
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def is_expired(self, header_value: str) -> bool:
        """
        Check if the cookie is expired.

        Args:
            header_value (str): The cookie header value.

        Returns:
            bool: True if the cookie is expired, False otherwise.
        """
        cookie = SimpleCookie(header_value)
        for key, morsel in cookie.items():
            expires = morsel.get('expires')
            if expires:
                try:
                    expire_time = parsedate_to_datetime(expires)
                    if expire_time is not None and expire_time < datetime.now(timezone.utc):
                        logging.info(f"Cookie '{key}' is expired (expires: {expire_time})")
                        return True
                    else:
                        logging.info(f"Cookie '{key}' is not expired (expires: {expire_time})")
                except (ValueError, TypeError) as e:
                    logging.error(f"Error parsing expiration date for cookie '{key}': {e}")
        return False
    
    def get_cookie_ignore_list(self):
        """
        Get the list of cookies to be ignored.

        Returns:
            set: A set of cookie names to be ignored.
        """
        # Implement a method to return the list of cookies to be ignored
        return set()

    def has_attribute(self, header_value: str, attribute: str) -> bool:
        """
        Check if the cookie has the specified attribute.

        Args:
            header_value (str): The cookie header value.
            attribute (str): The attribute to check for.

        Returns:
            bool: True if the attribute is present, False otherwise.
        """
        cookie = SimpleCookie(header_value)
        for key, morsel in cookie.items():
            if attribute.lower() == 'httponly' and morsel.get('httponly', False):
                return True
        return False
    
    def get_cookie_name(self, header_value: str) -> str:
        """
        Extract the cookie name.

        Args:
            header_value (str): The cookie header value.

        Returns:
            str: The name of the cookie.
        """
        cookie = SimpleCookie(header_value)
        for key in cookie.keys():
            return key
        return ""
    
    def __str__(self) -> str:
        """
        Returns a string representation of the CookieHttpOnlyScanRule object.

        Returns:
            str: A string representation of the CookieHttpOnlyScanRule object.
        """
        return "Cookie HttpOnly Flag"

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 1004  # CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 13  # WASC-13: Info leakage

