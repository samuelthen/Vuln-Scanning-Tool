import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
import base64

logger = logging.getLogger(__name__)

class XChromeLoggerDataInfoLeakScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for X-ChromeLogger-Data or X-ChromePhp-Data headers.
    """
    MSG_REF = "pscanrules.xchromeloggerdata"
    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for X-ChromeLogger-Data or X-ChromePhp-Data headers in the HTTP response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            # Get the header(s)
            xcld_headers = response.headers.get("X-ChromeLogger-Data")
            xcpd_headers = response.headers.get("X-ChromePhp-Data")

            logger_headers = []
            if xcld_headers:
                logger_headers.append(xcld_headers)
            if xcpd_headers:
                logger_headers.append(xcpd_headers)

            if logger_headers:
                for header_value in logger_headers:
                    return self.create_alert(header_value)

            return NoAlert()
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e))

    def create_alert(self, header_value: str) -> Alert:
        """
        Create an alert based on the detected header value.

        Args:
            header_value (str): The value of the detected header.

        Returns:
            Alert: The constructed Alert object.
        """
        try:
            decoded_value = base64.b64decode(header_value).decode('utf-8')
            other_info = f"Decoded header value: {decoded_value}"
        except Exception as e:
            other_info = f"Failed to decode header value: {header_value} ({str(e)})"

        return Alert(
            risk_category="Medium",
            description="X-ChromeLogger-Data or X-ChromePhp-Data header detected, possible information leak",
            msg_ref=self.MSG_REF,
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id(),
            evidence=header_value,
            other_info=other_info
        )

    def __str__(self) -> str:
        """
        Returns a string representation of the XChromeLoggerDataInfoLeakScanRule object.

        Returns:
            str: A string representation of the XChromeLoggerDataInfoLeakScanRule object.
        """
        return "X-ChromeLogger-Data Information Leak"

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 200  # CWE-200: Information Exposure

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 13  # WASC-13: Information Leakage
