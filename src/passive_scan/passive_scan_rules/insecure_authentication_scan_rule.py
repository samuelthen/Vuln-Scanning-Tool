import base64
import logging
import re
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class InsecureAuthenticationScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for insecure authentication mechanisms.
    """
    
    MSG_REF = "pscanrules.insecureauthentication"
    RISK = Risk.RISK_MEDIUM
    CONFIDENCE = Confidence.CONFIDENCE_MEDIUM

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
        CommonAlertTag.OWASP_2021_A02_CRYPTO_FAIL,
        CommonAlertTag.OWASP_2017_A02_BROKEN_AUTH,
        CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED,
        CommonAlertTag.WSTG_V42_ATHN_01_CREDS_NO_CRYPTO
    ]

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for insecure authentication mechanisms in the HTTP request.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            if request.url.startswith("https"):
                return NoAlert(msg_ref=self.MSG_REF)

            auth_headers = request.headers.get("Authorization", "")
            if auth_headers:
                for auth_header_value in auth_headers.split(","):
                    auth_mechanism = auth_header_value.split()[0].lower()
                    
                    if auth_mechanism == "basic":
                        return self.handle_basic_auth(auth_header_value)
                    elif auth_mechanism == "digest":
                        return self.handle_digest_auth(auth_header_value)
            
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)
        
    def handle_basic_auth(self, auth_header_value):
        try:
            auth_values = auth_header_value.split()
            if len(auth_values) == 2:
                encoded_credentials = auth_values[1]
                try:
                    decoded = base64.b64decode(encoded_credentials).decode('utf-8')
                except Exception as decode_error:
                    logger.error(f"Base64 decoding failed: {encoded_credentials}. Error: {decode_error}")
                    return ScanError(description=f"Invalid Base64 value: {encoded_credentials}", msg_ref=self.MSG_REF)
                
                username, password = decoded.split(":", 1) if ":" in decoded else (decoded, None)
                
                return Alert(
                    risk_category=Risk.RISK_HIGH if password else self.RISK,
                    confidence=Confidence.CONFIDENCE_MEDIUM,
                    description="Insecure Basic Authentication detected",
                    msg_ref=self.MSG_REF,
                    evidence=f"Username: {username}, Password: {'*' * len(password) if password else 'Not provided'}",
                    cwe_id=self.get_cwe_id(),
                    wasc_id=self.get_wasc_id()
                )
            else:
                logger.debug(f"Malformed Basic Authentication Header: {auth_header_value}")
                return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            logger.error(f"Error processing Basic Authentication: {auth_header_value}. Error: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)
    
    def handle_digest_auth(self, auth_header_value):
        try:
            username_match = re.search(r'username="?([^",]+)"?', auth_header_value, re.IGNORECASE)
            if username_match:
                username = username_match.group(1)
                return Alert(
                    risk_category=self.RISK,
                    confidence=Confidence.CONFIDENCE_MEDIUM,
                    description="Insecure Digest Authentication detected",
                    msg_ref=self.MSG_REF,
                    evidence=f"Username: {username}",
                    cwe_id=self.get_cwe_id(),
                    wasc_id=self.get_wasc_id()
                )
            else:
                logger.debug(f"Username not found in Digest Authentication Header: {auth_header_value}")
                return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            logger.error(f"Error processing Digest Authentication: {auth_header_value}. Error: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)
    
    def __str__(self) -> str:
        """
        Returns a string representation of the InsecureAuthenticationScanRule object.

        Returns:
            str: A string representation of the InsecureAuthenticationScanRule object.
        """
        return "Insecure Authentication Scan Rule"
    
    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 326  # CWE-326: Inadequate Encryption Strength

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 4  # WASC-4: Insufficient Transport Layer Protection
