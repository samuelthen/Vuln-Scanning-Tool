import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError

logger = logging.getLogger(__name__)

class XBackendServerInformationLeakScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for X-Backend-Server header information leak.
    """

    MSG_REF = "pscanrules.xbackendserver"

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for the X-Backend-Server header in the HTTP response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            # Check for X-Backend-Server header
            xbs_header = response.headers.get("X-Backend-Server")
            if xbs_header:
                return Alert(risk_category="Low", 
                             description="X-Backend-Server header information leak", 
                             msg_ref=self.MSG_REF,
                             cwe_id=self.get_cwe_id(), 
                             wasc_id=self.get_wasc_id(),
                             evidence=xbs_header)
            return NoAlert()
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e))
        
    def __str__(self) -> str:
        """
        Returns a string representation of the XBackendServerInformationLeakScanRule object.

        Returns:
            str: A string representation of the XBackendServerInformationLeakScanRule object.
        """
        return "X-Backend-Server Header Information Leak"
    
    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 200 # CWE-200: Information Exposure

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 13 # WASC-13: Information Leakage
