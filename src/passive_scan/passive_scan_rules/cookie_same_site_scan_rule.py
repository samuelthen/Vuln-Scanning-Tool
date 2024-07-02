import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class CookieSameSiteScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for the SameSite attribute in cookies.
    """
    MSG_REF = "pscanrules.cookiesamesite"
    RISK = Risk.RISK_LOW
    CONFIDENCE = Confidence.CONFIDENCE_MEDIUM

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
        CommonAlertTag.OWASP_2017_A05_BROKEN_AC,
        CommonAlertTag.WSTG_V42_SESS_02_COOKIE_ATTRS
    ]

    SAME_SITE_COOKIE_ATTRIBUTE = "SameSite"
    SAME_SITE_COOKIE_VALUE_STRICT = "Strict"
    SAME_SITE_COOKIE_VALUE_LAX = "Lax"
    SAME_SITE_COOKIE_VALUE_NONE = "None"

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for the SameSite attribute in cookies.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            cookies = response.headers.get('Set-Cookie')
            if not cookies:
                return NoAlert(msg_ref=self.MSG_REF)

            cookies_list = cookies.split(', ')
            for cookie in cookies_list:
                cookie_name = self.get_cookie_name(cookie)
                same_site_val = self.get_cookie_attribute(cookie, self.SAME_SITE_COOKIE_ATTRIBUTE)

                if same_site_val is None:
                    # SameSite attribute is missing
                    return self.build_alert(cookie, "Missing SameSite attribute in cookie")
                elif same_site_val.lower() == self.SAME_SITE_COOKIE_VALUE_NONE.lower():
                    # SameSite attribute is set to None and alert threshold is not high
                    return self.build_alert(cookie, "SameSite attribute set to None in cookie")
                elif same_site_val.lower() not in [self.SAME_SITE_COOKIE_VALUE_STRICT.lower(),
                                                   self.SAME_SITE_COOKIE_VALUE_LAX.lower(),
                                                   self.SAME_SITE_COOKIE_VALUE_NONE.lower()]:
                    # SameSite attribute has an illegal value
                    return self.build_alert(cookie, "SameSite attribute has an illegal value in cookie")

            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def build_alert(self, cookie: str, description: str) -> Alert:
        """
        Build an alert object for a given cookie issue.

        Args:
            cookie (str): The cookie string.
            description (str): Description of the alert.

        Returns:
            Alert: The constructed Alert object.
        """
        return Alert(risk_category=self.RISK,
                     confidence=self.CONFIDENCE,
                     description=description,
                     msg_ref=self.MSG_REF,
                     evidence=cookie,
                     cwe_id=self.get_cwe_id(),
                     wasc_id=self.get_wasc_id())

    def get_cookie_name(self, cookie: str) -> str:
        """
        Extract the name of the cookie.

        Args:
            cookie (str): The cookie string.

        Returns:
            str: The name of the cookie.
        """
        return cookie.split('=')[0].strip()

    def get_cookie_attribute(self, cookie: str, attribute: str) -> str:
        """
        Extract the value of a specified attribute from the cookie.

        Args:
            cookie (str): The cookie string.
            attribute (str): The attribute to extract.

        Returns:
            str: The value of the specified attribute.
        """
        attributes = cookie.split('; ')
        for attr in attributes:
            if attr.lower().startswith(attribute.lower()):
                return attr.split('=')[1].strip()
        return None

    def __str__(self) -> str:
        """
        Returns a string representation of the CookieSameSiteScanRule object.

        Returns:
            str: A string representation of the CookieSameSiteScanRule object.
        """
        return "Cookie SameSite Attribute"

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 1275 # CWE-1275: Sensitive Cookie with Improper SameSite Attribute

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 13 # WASC-13: Info leakage
