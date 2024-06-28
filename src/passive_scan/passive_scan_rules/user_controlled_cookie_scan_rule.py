import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class UserControlledCookieScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for user-controlled cookies.
    """
    MSG_REF = "pscanrules.usercontrolledcookie"
    RISK = Risk.RISK_INFO
    CONFIDENCE = Confidence.CONFIDENCE_LOW

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for user-controlled cookies in the HTTP response.

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

            params = self.get_request_params(request)
            if not params:
                return NoAlert(msg_ref=self.MSG_REF)

            for cookie in cookies.split(';'):
                decoded_cookie = self.decode_cookie(cookie, response.encoding)
                if not decoded_cookie:
                    continue

                cookie_parts = decoded_cookie.split('=|')
                for cookie_part in cookie_parts:
                    alert = self.check_user_controllable_cookie_header_value(request, response, params, cookie_part, decoded_cookie)
                    if alert:
                        return alert
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def decode_cookie(self, cookie: str, charset: str) -> str:
        """
        Decode the cookie using the specified charset or standard charsets.

        Args:
            cookie (str): The cookie to decode.
            charset (str): The charset to use for decoding.

        Returns:
            str: The decoded cookie.
        """
        try:
            return cookie.encode().decode(charset or 'utf-8')
        except (UnicodeDecodeError, TypeError):
            return None

    def check_user_controllable_cookie_header_value(self, request: Request, response: Response, params: dict, cookie_part: str, cookie: str) -> Alert:
        """
        Check if the cookie part matches user-controllable parameter values.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.
            params (dict): The user-controllable parameters.
            cookie_part (str): The part of the cookie to check.
            cookie (str): The full cookie string.

        Returns:
            Alert: An Alert object if a match is found, otherwise None.
        """
        for param_name, param_value in params.items():
            if param_value and len(param_value) > 1 and param_value == cookie_part:
                return Alert(
                    risk_category=self.RISK,
                    confidence=self.CONFIDENCE,
                    description="User-controlled cookie detected",
                    msg_ref=self.MSG_REF,
                    evidence=cookie,
                    cwe_id=self.get_cwe_id(),
                    wasc_id=self.get_wasc_id()
                )
        return None

    def get_request_params(self, request: Request) -> dict:
        """
        Extract parameters from the request.

        Args:
            request (Request): The HTTP request object.

        Returns:
            dict: A dictionary of parameters.
        """
        params = request.params.copy()
        if request.data:
            params.update(request.data)
        return params

    def __str__(self) -> str:
        """
        Returns a string representation of the UserControlledCookieScanRule object.

        Returns:
            str: A string representation of the UserControlledCookieScanRule object.
        """
        return "User Controlled Cookie Scan Rule"

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 565  # CWE-565: Reliance on Cookies without Validation and Integrity Checking

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 20  # WASC-20: Improper Input Handling