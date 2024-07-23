import logging
import re
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class InformationDisclosureSuspiciousCommentsScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for suspicious comments in HTTP responses.
    """
    MSG_REF = "pscanrules.informationdisclosuresuspiciouscomments"
    RISK = Risk.RISK_INFO
    CONFIDENCE = Confidence.CONFIDENCE_MEDIUM

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
        CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED,
        CommonAlertTag.WSTG_V42_INFO_05_CONTENT_LEAK
    ]

    DEFAULT_PAYLOADS = [
        "TODO", "FIXME", "BUG", "BUGS", "XXX", "QUERY", "DB",
        "ADMIN", "ADMINISTRATOR", "USER", "USERNAME", "SELECT",
        "WHERE", "FROM", "LATER", "DEBUG"
    ]

    def __init__(self):
        """
        Initialize the scan rule with the list of default payloads.
        """
        self.patterns = [re.compile(rf"\b{payload}\b", re.IGNORECASE) for payload in self.DEFAULT_PAYLOADS]

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for suspicious comments in HTTP response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            response_body = response.text
            if response_body:
                alert_map = self.scan_for_suspicious_comments(response_body)
                if alert_map:
                    evidence = []
                    for pattern, details in alert_map.items():
                        details = list(set(details))
                        evidence.extend(details)
                    if evidence:
                        description = f"Suspicious comments found: {', '.join(evidence)}"
                        return Alert(
                            risk_category=self.RISK,
                            confidence=self.CONFIDENCE,
                            msg_ref=self.MSG_REF,
                            evidence=str(evidence),
                            description=description,
                            cwe_id=self.get_cwe_id(),
                            wasc_id=self.get_wasc_id()
                        )
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def scan_for_suspicious_comments(self, response_body: str) -> dict:
        """
        Scan the response body for suspicious comments.

        Args:
            response_body (str): The response body to scan.

        Returns:
            dict: A dictionary with patterns as keys and list of details as values.
        """
        alert_map = {}
        for pattern in self.patterns:
            matches = pattern.findall(response_body)
            if matches:
                alert_map[pattern.pattern] = matches
        return alert_map

    def __str__(self) -> str:
        """
        Returns a string representation of the InformationDisclosureSuspiciousCommentsScanRule object.

        Returns:
            str: A string representation of the InformationDisclosureSuspiciousCommentsScanRule object.
        """
        return "Information Disclosure Suspicious Comments"

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
