import logging
import re
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class HeartBleedScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for vulnerable OpenSSL versions indicating the HeartBleed vulnerability.
    """

    MSG_REF = "pscanrules.heartbleed"
    RISK = Risk.RISK_HIGH
    CONFIDENCE = Confidence.CONFIDENCE_LOW

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A06_VULN_COMP,
        CommonAlertTag.OWASP_2017_A09_VULN_COMP,
        CommonAlertTag.WSTG_V42_CRYP_01_TLS
    ]

    # Pattern to identify the OpenSSL version in the response headers
    openSSLversionPattern = re.compile(r'Server:.*?(OpenSSL/([0-9.]+[a-z-0-9]+))', re.IGNORECASE)
    
    # Vulnerable versions
    openSSLvulnerableVersions = [
        "1.0.1-Beta1",
        "1.0.1-Beta2",
        "1.0.1-Beta3",
        "1.0.1",
        "1.0.1a",
        "1.0.1b",
        "1.0.1c",
        "1.0.1d",
        "1.0.1e",
        "1.0.1f",
        "1.0.2-beta"
    ]

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for vulnerable OpenSSL versions in the HTTP response headers.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            response_headers = response.headers

            # Match the OpenSSL version pattern
            matcher = self.openSSLversionPattern.search(response_headers.get('Server', ''))
            if matcher:
                full_version_string = matcher.group(1)  # e.g., OpenSSL/1.0.1e
                version_number = matcher.group(2)  # e.g., 1.0.1e

                # Check if the version matches any known vulnerable versions
                if version_number in self.openSSLvulnerableVersions:
                    return Alert(
                        risk_category=self.RISK,
                        confidence=self.CONFIDENCE,
                        description="OpenSSL version is vulnerable to HeartBleed",
                        msg_ref=self.MSG_REF,
                        cwe_id=self.get_cwe_id(),
                        wasc_id=self.get_wasc_id(),
                        evidence=full_version_string
                    )
            
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)
        
    def __str__(self) -> str:
        """
        Returns a string representation of the HeartBleedScanRule object.

        Returns:
            str: A string representation of the HeartBleedScanRule object.
        """
        return "HeartBleed Vulnerability Scan Rule"
    
    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 119  # CWE-119: Failure to Constrain Operations within the Bounds of a Memory Buffer

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 20  # WASC-20: Improper Input Handling
