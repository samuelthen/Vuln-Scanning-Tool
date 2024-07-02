import logging
import re
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class InformationDisclosureInUrlScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for information disclosure in URL parameters.
    """
    MSG_REF = "pscanrules.informationdisclosureinurl"
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

    # List of sensitive words to check in URL parameters
    SENSITIVE_WORDS = [
        "user", "username", "pass", "password", "pwd",
        "token", "ticket", "session", "jsessionid", "sessionid"
    ]

    def __init__(self):
        """
        Initialize the scan rule with the list of sensitive words.
        """
        self.sensitive_words = self.SENSITIVE_WORDS

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for sensitive information in URL parameters.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            # Get URL parameters from the request
            url_params = request.params
            for param, value in url_params.items():
                # Check if parameter name contains sensitive information
                sensitive_info = self.contains_sensitive_information(param)
                if sensitive_info:
                    return Alert(
                        risk_category=self.RISK,
                        confidence=self.CONFIDENCE,
                        msg_ref=self.MSG_REF,
                        description=f"Sensitive information found in URL parameter: {sensitive_info}",
                        cwe_id=self.get_cwe_id(),
                        wasc_id=self.get_wasc_id()
                    )
                # Check if parameter value is a credit card number
                if self.is_credit_card(value):
                    return Alert(
                        risk_category=self.RISK,
                        confidence=self.CONFIDENCE,
                        msg_ref=self.MSG_REF,
                        description="Credit card number found in URL parameter",
                        cwe_id=self.get_cwe_id(),
                        wasc_id=self.get_wasc_id()
                    )
                # Check if parameter value is an email address
                if self.is_email_address(value):
                    return Alert(
                        risk_category=self.RISK,
                        confidence=self.CONFIDENCE,
                        msg_ref=self.MSG_REF,
                        description="Email address found in URL parameter",
                        cwe_id=self.get_cwe_id(),
                        wasc_id=self.get_wasc_id()
                    )
                # Check if parameter value is a US Social Security Number
                if self.is_us_ssn(value):
                    return Alert(
                        risk_category=self.RISK,
                        confidence=self.CONFIDENCE,
                        msg_ref=self.MSG_REF,
                        description="US Social Security Number found in URL parameter",
                        cwe_id=self.get_cwe_id(),
                        wasc_id=self.get_wasc_id()
                    )
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def contains_sensitive_information(self, param_name: str) -> str:
        """
        Check if the parameter name contains sensitive information.

        Args:
            param_name (str): The name of the URL parameter.

        Returns:
            str: The sensitive word found in the parameter name, or None if not found.
        """
        param_name_lower = param_name.lower()
        for word in self.sensitive_words:
            if word in param_name_lower:
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

    def __str__(self) -> str:
        """
        Returns a string representation of the InformationDisclosureInUrlScanRule object.

        Returns:
            str: A string representation of the InformationDisclosureInUrlScanRule object.
        """
        return "Information Disclosure in URL"

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
