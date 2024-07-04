import logging
import re
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag
from .utils.binlist import BinList

logger = logging.getLogger(__name__)

class InformationDisclosureReferrerScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for information disclosure in HTTP Referrer headers.
    """
    MSG_REF = "pscanrules.informationdisclosurereferrer"
    RISK = Risk.RISK_INFO
    CONFIDENCE = Confidence.CONFIDENCE_MEDIUM

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
        CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED
    ]    
    # Regular expressions for detecting sensitive information patterns
    EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}\b")
    CREDIT_CARD_PATTERN = re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|"
        r"3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b"
    )
    US_SSN_PATTERN = re.compile(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b")

    # List of sensitive words to check in referrer URLs
    SENSITIVE_WORDS = [
        "user", "username", "pass", "password", "pwd",
        "token", "ticket", "session", "jsessionid", "sessionid"
    ]

    def __init__(self):
        """
        Initialize the scan rule with the list of sensitive words.
        """
        self.sensitive_words = self.SENSITIVE_WORDS

    # class BinList:
    #     """
    #     Mock class for BinList to simulate BIN record lookup.
    #     """
    #     BIN_RECORDS = {
    #         '411111': 'Visa',
    #         '550000': 'MasterCard',
    #         '340000': 'American Express',
    #         '300000': 'Diners Club',
    #         '601100': 'Discover',
    #         '201400': 'EnRoute',
    #         '213100': 'JCB'
    #     }

    #     @staticmethod
    #     def get(card_number: str) -> str:
    #         bin_number = card_number[:6]
    #         return InformationDisclosureReferrerScanRule.BinList.BIN_RECORDS.get(bin_number, None)

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for sensitive information in HTTP Referrer headers.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            referrer_headers = request.headers.get('Referer', [])
            if not referrer_headers:
                return NoAlert(msg_ref=self.MSG_REF)
            
            for referrer in referrer_headers:
                # Check if the referrer is from a different domain
                if not self.is_same_domain(request.url, referrer):
                    # Check for sensitive information in the referrer URL
                    sensitive_info = self.contains_sensitive_information(referrer)
                    if sensitive_info:
                        return Alert(
                            risk_category=self.RISK,
                            confidence=self.CONFIDENCE,
                            msg_ref=self.MSG_REF,
                            description=f"Sensitive information found in Referrer header: {sensitive_info}",
                            cwe_id=self.get_cwe_id(),
                            wasc_id=self.get_wasc_id()
                        )
                    # Check for credit card information in the referrer URL
                    if self.is_credit_card(referrer):
                        bin_record = BinList.get_singleton().get(referrer)
                        
                        description = "Credit card number found in Referrer header"
                        if bin_record:
                            description += f" with BIN record: {bin_record}"
                        return Alert(
                            risk_category=self.RISK,
                            confidence=self.CONFIDENCE if not bin_record else Risk.RISK_HIGH,
                            msg_ref=self.MSG_REF,
                            evidence=bin_record,
                            description=f"{referrer}. description",
                            cwe_id=self.get_cwe_id(),
                            wasc_id=self.get_wasc_id()
                        )
                    # Check for email address in the referrer URL
                    if self.is_email_address(referrer):
                        return Alert(
                            risk_category=self.RISK,
                            confidence=self.CONFIDENCE,
                            msg_ref=self.MSG_REF,
                            description="Email address found in Referrer header",
                            cwe_id=self.get_cwe_id(),
                            wasc_id=self.get_wasc_id()
                        )
                    # Check for US Social Security Number in the referrer URL
                    if self.is_us_ssn(referrer):
                        return Alert(
                            risk_category=self.RISK,
                            confidence=self.CONFIDENCE,
                            msg_ref=self.MSG_REF,
                            description="US Social Security Number found in Referrer header",
                            cwe_id=self.get_cwe_id(),
                            wasc_id=self.get_wasc_id()
                        )
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def contains_sensitive_information(self, referrer: str) -> str:
        """
        Check if the referrer URL contains sensitive information.

        Args:
            referrer (str): The referrer URL.

        Returns:
            str: The sensitive word found in the referrer URL, or None if not found.
        """
        referrer_lower = referrer.lower()
        for word in self.sensitive_words:
            if word in referrer_lower:
                return word
        return None

    def is_email_address(self, value: str) -> bool:
        """
        Check if the value is an email address.

        Args:
            value (str): The value to check.

        Returns:
            bool: True if the value is an email address, False otherwise.
        """
        return bool(self.EMAIL_PATTERN.search(value))

    def is_credit_card(self, value: str) -> bool:
        """
        Check if the value is a credit card number.

        Args:
            value (str): The value to check.

        Returns:
            bool: True if the value is a credit card number, False otherwise.
        """
        return bool(self.CREDIT_CARD_PATTERN.search(value))

    def is_us_ssn(self, value: str) -> bool:
        """
        Check if the value is a US Social Security Number.

        Args:
            value (str): The value to check.

        Returns:
            bool: True if the value is a US Social Security Number, False otherwise.
        """
        return bool(self.US_SSN_PATTERN.search(value))

    def is_same_domain(self, url: str, referrer: str) -> bool:
        """
        Check if the referrer URL is from the same domain as the request URL.

        Args:
            url (str): The request URL.
            referrer (str): The referrer URL.

        Returns:
            bool: True if the referrer is from the same domain, False otherwise.
        """
        from urllib.parse import urlparse
        try:
            url_host = urlparse(url).hostname
            referrer_host = urlparse(referrer).hostname
            return url_host and referrer_host and url_host.lower() == referrer_host.lower()
        except Exception as e:
            logger.error(f"Error parsing URLs: {e}")
            return False

    def __str__(self) -> str:
        """
        Returns a string representation of the InformationDisclosureReferrerScanRule object.

        Returns:
            str: A string representation of the InformationDisclosureReferrerScanRule object.
        """
        return "Information Disclosure in Referrer Header"

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
