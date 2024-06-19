import logging
import re
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError

logger = logging.getLogger(__name__)

class InformationDisclosureInUrlScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for information disclosure in URL parameters.
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

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for sensitive information in URL parameters.
        """
        try:
            url_params = request.params
            for param, value in url_params.items():
                sensitive_info = self.contains_sensitive_information(param)
                if sensitive_info:
                    return Alert(
                        risk_category="Informational",
                        description=f"Sensitive information found in URL parameter: {sensitive_info}",
                        msg_ref="pscanrules.informationdisclosureinurl",
                        cwe_id=self.get_cwe_id(),
                        wasc_id=self.get_wasc_id()
                    )
                if self.is_credit_card(value):
                    return Alert(
                        risk_category="Informational",
                        description="Credit card number found in URL parameter",
                        msg_ref="pscanrules.informationdisclosureinurl",
                        cwe_id=self.get_cwe_id(),
                        wasc_id=self.get_wasc_id()
                    )
                if self.is_email_address(value):
                    return Alert(
                        risk_category="Informational",
                        description="Email address found in URL parameter",
                        msg_ref="pscanrules.informationdisclosureinurl",
                        cwe_id=self.get_cwe_id(),
                        wasc_id=self.get_wasc_id()
                    )
                if self.is_us_ssn(value):
                    return Alert(
                        risk_category="Informational",
                        description="US Social Security Number found in URL parameter",
                        msg_ref="pscanrules.informationdisclosureinurl",
                        cwe_id=self.get_cwe_id(),
                        wasc_id=self.get_wasc_id()
                    )
            return NoAlert()
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e))

    def contains_sensitive_information(self, param_name: str) -> str:
        """
        Check if the parameter name contains sensitive information.
        """
        param_name_lower = param_name.lower()
        for word in self.sensitive_words:
            if word in param_name_lower:
                return word
        return None

    def is_email_address(self, value: str) -> bool:
        return bool(self.EMAIL_PATTERN.search(value))

    def is_credit_card(self, value: str) -> bool:
        return bool(self.CREDIT_CARD_PATTERN.search(value))

    def is_us_ssn(self, value: str) -> bool:
        return bool(self.US_SSN_PATTERN.search(value))

    def __str__(self) -> str:
        return "Information Disclosure in URL"

    def get_cwe_id(self):
        return 200  # CWE-200: Information Exposure

    def get_wasc_id(self):
        return 13  # WASC-13: Information Leakage
