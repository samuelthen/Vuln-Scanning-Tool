import logging
import hashlib
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class UsernameIdorScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for usernames or their hashes in HTTP responses.
    """
    MSG_REF = "pscanrules.usernameidor"
    RISK = Risk.RISK_INFO
    CONFIDENCE = Confidence.CONFIDENCE_HIGH

    DEFAULT_USERNAMES = ["Admin", "admin"]

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
        CommonAlertTag.OWASP_2017_A05_BROKEN_AC,
        CommonAlertTag.WSTG_V42_ATHZ_04_IDOR
    ]

    def __init__(self):
        self.payload_provider = self.default_payload_provider

    def default_payload_provider(self):
        return self.DEFAULT_USERNAMES

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for usernames or their hashes in the HTTP response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            scan_users = self.get_users()
            if not scan_users:
                logger.debug("There does not appear to be any contexts with configured users.")
                return NoAlert(msg_ref=self.MSG_REF)

            response_content = str(response.headers) + response.text
            for user in scan_users:
                username = user
                hashes = self.compute_hashes(username)
                for hash_type, hash_value in hashes.items():
                    if hash_value in response_content:
                        return self.create_alert(username, hash_value, hash_type)

            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def get_users(self):
        """
        Get the list of users to check for in the response.

        Returns:
            list: List of usernames.
        """
        return self.payload_provider()

    def compute_hashes(self, username: str) -> dict:
        """
        Compute various hash values for a given username.

        Args:
            username (str): The username to hash.

        Returns:
            dict: A dictionary of hash type to hash value.
        """
        hashes = {
            'MD5': hashlib.md5(username.encode()).hexdigest(),
            'SHA1': hashlib.sha1(username.encode()).hexdigest(),
            'SHA256': hashlib.sha256(username.encode()).hexdigest(),
            'SHA384': hashlib.sha384(username.encode()).hexdigest(),
            'SHA512': hashlib.sha512(username.encode()).hexdigest(),
        }
        return hashes

    def create_alert(self, username: str, evidence: str, hash_type: str) -> Alert:
        """
        Create an alert based on the detected username or its hash.

        Args:
            username (str): The username detected.
            evidence (str): The hash value detected in the response.
            hash_type (str): The type of hash detected.

        Returns:
            Alert: The constructed Alert object.
        """
        return Alert(
            risk_category=self.RISK,
            confidence=self.CONFIDENCE,
            description=self.get_description(username),
            msg_ref=self.MSG_REF,
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id(),
            evidence=evidence,
            other_info=f"Detected {hash_type} hash of username {username}: {evidence}"
        )

    def get_description(self, username: str) -> str:
        """
        Get the description for the alert.

        Args:
            username (str): The username detected.

        Returns:
            str: The description string.
        """
        return f"Username or hash detected in response: {username}"

    def __str__(self) -> str:
        """
        Returns a string representation of the UsernameIdorScanRule object.

        Returns:
            str: A string representation of the UsernameIdorScanRule object.
        """
        return "Username IDOR Scan Rule"

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 284  # CWE-284: Improper Access Control

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 2  # WASC-02: Insufficient Authorization

