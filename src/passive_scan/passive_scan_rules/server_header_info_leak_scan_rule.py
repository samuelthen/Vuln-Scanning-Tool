import logging
import re
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class ServerHeaderInfoLeakScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for server header version information leaks.
    """

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
        CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
        CommonAlertTag.WSTG_V42_INFO_02_FINGERPRINT_WEB_SERVER
    ]

    VERSION_PATTERN = re.compile(r".*\d.*")

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for server header version information leaks in the HTTP response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            server_headers = response.headers.get("Server")
            if server_headers:
                for server_header in server_headers.split(","):
                    server_header = server_header.strip()
                    if self.VERSION_PATTERN.match(server_header):
                        return Alert(
                            risk_category=Risk.RISK_LOW, 
                            confidence=Confidence.CONFIDENCE_HIGH,
                            description="Server version information leak",
                            msg_ref="pscanrules.serverheaderversioninfoleak",
                            cwe_id=self.get_cwe_id(), 
                            wasc_id=self.get_wasc_id(),
                            evidence=server_header
                        )
                    else:
                        return Alert(
                            risk_category=Risk.RISK_INFO, 
                            confidence=Confidence.CONFIDENCE_HIGH,
                            description="Server header present",
                            msg_ref="pscanrules.serverheaderinfoleak",
                            cwe_id=self.get_cwe_id(), 
                            wasc_id=self.get_wasc_id(),
                            evidence=server_header
                        )
            return NoAlert(msg_ref="pscanrules.serverheaderinfoleak")
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref="pscanrules.serverheaderinfoleak")

    def __str__(self) -> str:
        """
        Returns a string representation of the ServerHeaderInfoLeakScanRule object.

        Returns:
            str: A string representation of the ServerHeaderInfoLeakScanRule object.
        """
        return "Server Header Information Leak"

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
