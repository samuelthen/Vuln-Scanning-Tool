import logging
import re
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError

logger = logging.getLogger(__name__)

class InformationDisclosureReferrerScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for information disclosure in HTTP Referrer headers.
    """
    
    EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}\b")
    CREDIT_CARD_PATTERN = re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|"
        r"3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b"
    )
    US_SSN_PATTERN = re.compile(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b")

    SENSITIVE_WORDS = [
        "user", "username", "pass", "password", "pwd",
        "token", "ticket", "session", "jsessionid", "sessionid"
    ]

    def __init__(self):
        self.sensitive_words = self.SENSITIVE_WORDS

    class BinList:
        """
        Mock class for BinList to simulate BIN record lookup.
        """
        BIN_RECORDS = {
            '411111': 'Visa',
            '550000': 'MasterCard',
            '340000': 'American Express',
            '300000': 'Diners Club',
            '601100': 'Discover',
            '201400': 'EnRoute',
            '213100': 'JCB'
        }

        @staticmethod
        def get(card_number: str) -> str:
            bin_number = card_number[:6]
            return InformationDisclosureReferrerScanRule.BinList.BIN_RECORDS.get(bin_number, None)

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for sensitive information in HTTP Referrer headers.
        """
        try:
            referrer_headers = request.headers.get('Referer', [])
            if not referrer_headers:
                return NoAlert()
            
            for referrer in referrer_headers:
                if not self.is_same_domain(request.url, referrer):
                    sensitive_info = self.contains_sensitive_information(referrer)
                    if sensitive_info:
                        return Alert(
                            risk_category="Informational",
                            description=f"Sensitive information found in Referrer header: {sensitive_info}",
                            msg_ref="pscanrules.informationdisclosurereferrer",
                            cwe_id=self.get_cwe_id(),
                            wasc_id=self.get_wasc_id()
                        )
                    if self.is_credit_card(referrer):
                        bin_record = self.BinList.get(referrer)
                        description = "Credit card number found in Referrer header"
                        if bin_record:
                            description += f" with BIN record: {bin_record}"
                        return Alert(
                            risk_category="Informational",
                            description=description,
                            msg_ref="pscanrules.informationdisclosurereferrer",
                            cwe_id=self.get_cwe_id(),
                            wasc_id=self.get_wasc_id()
                        )
                    if self.is_email_address(referrer):
                        return Alert(
                            risk_category="Informational",
                            description="Email address found in Referrer header",
                            msg_ref="pscanrules.informationdisclosurereferrer",
                            cwe_id=self.get_cwe_id(),
                            wasc_id=self.get_wasc_id()
                        )
                    if self.is_us_ssn(referrer):
                        return Alert(
                            risk_category="Informational",
                            description="US Social Security Number found in Referrer header",
                            msg_ref="pscanrules.informationdisclosurereferrer",
                            cwe_id=self.get_cwe_id(),
                            wasc_id=self.get_wasc_id()
                        )
            return NoAlert()
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e))

    def contains_sensitive_information(self, referrer: str) -> str:
        """
        Check if the referrer URL contains sensitive information.
        """
        referrer_lower = referrer.lower()
        for word in self.sensitive_words:
            if word in referrer_lower:
                return word
        return None

    def is_email_address(self, value: str) -> bool:
        return bool(self.EMAIL_PATTERN.search(value))

    def is_credit_card(self, value: str) -> bool:
        return bool(self.CREDIT_CARD_PATTERN.search(value))

    def is_us_ssn(self, value: str) -> bool:
        return bool(self.US_SSN_PATTERN.search(value))

    def is_same_domain(self, url: str, referrer: str) -> bool:
        """
        Check if the referrer URL is from the same domain as the request URL.
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
        return "Information Disclosure in Referrer Header"

    def get_cwe_id(self):
        return 200  # CWE-200: Information Exposure

    def get_wasc_id(self):
        return 13  # WASC-13: Information Leakage
