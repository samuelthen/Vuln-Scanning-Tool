import logging
import os
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class InformationDisclosureDebugErrorsScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for information disclosure in debug error messages.
    """
    MSG_REF = "pscanrules.informationdisclosuredebugerrors"
    RISK = Risk.RISK_LOW
    CONFIDENCE = Confidence.CONFIDENCE_MEDIUM

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
        CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED,
        CommonAlertTag.WSTG_V42_ERRH_01_ERR
    ]

    DEBUG_ERROR_FILE = "src/passive_scan/passive_scan_rules/utils/debug-error-messages.txt"

    def __init__(self):
        """
        Initialize the scan rule with the list of debug error messages.
        """
        self.errors = self.load_errors()

    def load_errors(self):
        """
        Load debug error messages from a file.

        Returns:
            list: A list of debug error messages.
        """
        errors = []
        try:
            with open(self.DEBUG_ERROR_FILE, 'r') as file:
                for line in file:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        errors.append(line.lower())
        except FileNotFoundError:
            logger.error(f"Debug error messages file not found: {self.DEBUG_ERROR_FILE}")
        except IOError as e:
            logger.error(f"Error reading debug error messages file: {e}")
        return errors

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for debug error messages in the HTTP response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            # Ensure the response is textual
            if not response.headers.get('Content-Type', '').startswith('text'):
                return NoAlert(msg_ref=self.MSG_REF)

            body = response.text.lower()
            for error in self.errors:
                if error in body:
                    return Alert(
                        risk_category=self.RISK,
                        confidence=self.CONFIDENCE,
                        msg_ref=self.MSG_REF,
                        evidence=error,
                        description=f"Debug error message found: {error}",
                        cwe_id=self.get_cwe_id(),
                        wasc_id=self.get_wasc_id()
                    )
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def __str__(self) -> str:
        """
        Returns a string representation of the InformationDisclosureDebugErrorsScanRule object.

        Returns:
            str: A string representation of the InformationDisclosureDebugErrorsScanRule object.
        """
        return "Information Disclosure Debug Errors"

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
