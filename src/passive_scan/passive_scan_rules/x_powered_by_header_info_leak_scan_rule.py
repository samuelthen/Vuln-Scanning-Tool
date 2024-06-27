import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError

logger = logging.getLogger(__name__)

class XPoweredByHeaderInfoLeakScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for X-Powered-By information leak in HTTP headers.
    """
    HEADER_NAME = "X-Powered-By"

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for X-Powered-By header in the HTTP response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            xpb_headers = self.get_x_powered_by_headers(response)
            if xpb_headers:
                alert_evidence = xpb_headers[0]
                alert_other_info = ""
                if len(xpb_headers) > 1:  # Multiple X-Powered-By headers found
                    alert_other_info = "\n".join(xpb_headers[1:])
                return Alert(risk_category="Low",
                             description="X-Powered-By header information leak",
                             msg_ref="pscanrules.xpoweredbyheaderinfoleak",
                             evidence=alert_evidence,
                             cwe_id=self.get_cwe_id(),
                             wasc_id=self.get_wasc_id())
            return NoAlert()
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e))
    
    def get_x_powered_by_headers(self, response: Response) -> list:
        """
        Extracts the list of X-Powered-By headers.

        Args:
            response (Response): The HTTP response object.

        Returns:
            list: A list of the matched headers.
        """
        matched_headers = []
        headers = response.headers
        for header_name, header_value in headers.items():
            if header_name.lower() == self.HEADER_NAME.lower():
                matched_headers.append(f"{header_name}: {header_value}")
        return matched_headers

    def __str__(self) -> str:
        """
        Returns a string representation of the XPoweredByHeaderInfoLeakScanRule object.

        Returns:
            str: A string representation of the XPoweredByHeaderInfoLeakScanRule object.
        """
        return "X-Powered-By Header Information Leak"
    
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
        return 13  # WASC-13: Info leakage
