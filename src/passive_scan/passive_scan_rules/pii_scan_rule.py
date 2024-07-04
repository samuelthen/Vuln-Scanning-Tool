import logging
import re
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag
from .utils.pii_utils import PiiUtils
from .utils.binlist import BinList

logger = logging.getLogger(__name__)

class PiiScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for the presence of PII in responses, specifically credit card numbers.
    """
    MSG_REF = "pscanrules.pii"
    RISK = Risk.RISK_HIGH
    CONFIDENCE = Confidence.CONFIDENCE_HIGH

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN,
        CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED
    ]

    CREDIT_CARD_PATTERNS = {
        "American Express": re.compile(r"\b(?:3[47][0-9]{13})\b"),
        "DinersClub": re.compile(r"\b(?:3(?:0[0-5]|[68][0-9])[0-9]{11})\b"),
        "Discover": re.compile(r"\b(?:6(?:011|5[0-9]{2})(?:[0-9]{12}))\b"),
        "JCB": re.compile(r"\b(?:(?:2131|1800|35\d{3})\d{11})\b"),
        "Maestro": re.compile(r"\b(?:(?:5[0678]\d\d|6304|6390|67\d\d)\d{8,15})\b"),
        "Mastercard": re.compile(r"\b(?:(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12})\b"),
        "Visa": re.compile(r"\b(?:4[0-9]{12})(?:[0-9]{3})?\b")
    }

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for the presence of PII in the response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            if not self.is_message_suitable(response):
                return NoAlert(msg_ref=self.MSG_REF)

            response_body = self.get_response_body_without_styles(response)

            for card_type, pattern in self.CREDIT_CARD_PATTERNS.items():
                matches = pattern.finditer(response_body)
                for match in matches:
                    evidence = match.group()
                    if PiiUtils.is_valid_luhn(evidence):
                        bin_rec = BinList.get_singleton().get(evidence)
                        return self.create_alert(evidence, card_type, bin_rec)
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def is_message_suitable(self, response: Response) -> bool:
        """
        Check if the response is suitable for scanning.

        Args:
            response (Response): The HTTP response object.

        Returns:
            bool: True if the response is suitable, False otherwise.
        """
        content_type = response.headers.get('Content-Type', '').lower()
        return "text" in content_type or "html" in content_type

    def get_response_body_without_styles(self, response: Response) -> str:
        """
        Remove style elements and attributes from the response body.

        Args:
            response (Response): The HTTP response object.

        Returns:
            str: The cleaned response body.
        """
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        for style in soup(['style']):
            style.decompose()
        for tag in soup():
            tag.attrs = {key: value for key, value in tag.attrs.items() if key.lower() != 'style'}
        return soup.get_text()

    def create_alert(self, evidence: str, card_type: str, bin_rec: dict) -> Alert:
        """
        Create an alert for a detected PII.

        Args:
            evidence (str): The evidence of the PII.
            card_type (str): The type of the credit card.
            bin_rec (dict): The BIN record information.

        Returns:
            Alert: The created alert object.
        """
        other_info = f"Card Type: {card_type}"
        if bin_rec:
            other_info += f"{bin_rec}"
        
        return Alert(
            risk_category=self.RISK,
            confidence=self.CONFIDENCE if bin_rec else Risk.RISK_MEDIUM,
            description="PII detected: Credit card number",
            msg_ref=self.MSG_REF,
            evidence=f"{evidence}. Other info: {other_info}",
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id()
        )

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 359  # CWE-359: Exposure of Private Information ('Privacy Violation')

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 13  # WASC-13: Information Leakage

    def __str__(self) -> str:
        """
        Returns a string representation of the PiiScanRule object.

        Returns:
            str: A string representation of the PiiScanRule object.
        """
        return "PII Scan Rule"
