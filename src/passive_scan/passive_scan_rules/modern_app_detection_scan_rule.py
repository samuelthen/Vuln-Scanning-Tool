import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class ModernAppDetectionScanRule(BasePassiveScanRule):
    """
    Passive scan rule to detect modern web applications by inspecting HTML responses.
    """
    MSG_REF = "pscanrules.modernapp"
    RISK = Risk.RISK_INFO
    CONFIDENCE = Confidence.CONFIDENCE_MEDIUM

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check the response for indications that it is a modern web application.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            # Only check HTML responses
            if not response.headers.get('Content-Type', '').startswith('text/html'):
                return NoAlert(msg_ref=self.MSG_REF)

            evidence = None
            other_info = None

            soup = BeautifulSoup(response.text, 'html.parser')

            links = soup.find_all('a')
            if not links:
                scripts = soup.find_all('script')
                if scripts:
                    evidence = str(scripts[0])
                    other_info = "No links found but scripts are present"
            else:
                for link in links:
                    href = link.get('href')
                    if not href or href == "#":
                        evidence = str(link)
                        other_info = "Links with empty href or # found"
                        break
                    target = link.get('target')
                    if target and target == "_self":
                        evidence = str(link)
                        other_info = "Links with target='_self' found"
                        break

            if not evidence:
                noscript = soup.find('noscript')
                if noscript:
                    evidence = str(noscript)
                    other_info = "Noscript tag found, indicating different behavior with JavaScript disabled"

            if evidence:
                return Alert(
                    risk_category=self.RISK,
                    confidence=self.CONFIDENCE,
                    description="Indication of a modern web application",
                    msg_ref=self.MSG_REF,
                    evidence=evidence,
                    other_info=other_info,
                    cwe_id=self.get_cwe_id(),
                    wasc_id=self.get_wasc_id()
                )
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def __str__(self) -> str:
        """
        Returns a string representation of the ModernAppDetectionScanRule object.

        Returns:
            str: A string representation of the ModernAppDetectionScanRule object.
        """
        return "Modern Application Detection Scan Rule"

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 829  # CWE-829: Inclusion of Functionality from Untrusted Control Sphere

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 20  # WASC-20: Improper Input Handling
