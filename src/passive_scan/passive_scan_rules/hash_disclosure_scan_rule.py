import logging
import re
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class HashDisclosureScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for hash signatures in HTTP requests and responses.
    """
    MSG_REF = "pscanrules.hashdisclosure"

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN,
        CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED
    ]

    # Define hash patterns and their corresponding alerts
    # Traditional DES: causes *way* too many false positives to enable this
    hash_patterns = {
        re.compile(r"\$LM\$[a-f0-9]{16}", re.IGNORECASE): ("LanMan / DES", "High", "High"),
        re.compile(r"\$K4\$[a-f0-9]{16}", re.IGNORECASE): ("Kerberos AFS DES", "High", "High"),
        re.compile(r"\$2a\$05\$[a-z0-9\+\-_./=]{53}", re.IGNORECASE): ("OpenBSD Blowfish", "High", "High"),
        re.compile(r"\$2y\$05\$[a-z0-9\+\-_./=]{53}", re.IGNORECASE): ("OpenBSD Blowfish", "High", "High"),
        re.compile(r"\$1\$[./0-9A-Za-z]{0,8}\$[./0-9A-Za-z]{1,22}"): ("MD5 Crypt", "High", "High"),
        re.compile(r"\$5\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{43}"): ("SHA-256 Crypt", "High", "High"),
        re.compile(r"\$5\$rounds=[0-9]+\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{43}"): ("SHA-256 Crypt", "High", "High"),
        re.compile(r"\$6\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{86}"): ("SHA-512 Crypt", "High", "High"),
        re.compile(r"\$6\$rounds=[0-9]+\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{86}"): ("SHA-512 Crypt", "High", "High"),
        re.compile(r"\$2\$[0-9]{2}\$[./0-9A-Za-z]{53}"): ("BCrypt", "High", "High"),
        re.compile(r"\$2a\$[0-9]{2}\$[./0-9A-Za-z]{53}"): ("BCrypt", "High", "High"),
        re.compile(r"\$3\$\$[0-9a-f]{32}"): ("NTLM", "High", "High"),
        re.compile(r"\$NT\$[0-9a-f]{32}"): ("NTLM", "High", "High"),
        re.compile(r"\b[0-9A-F]{48}\b"): ("Mac OSX salted SHA-1", "High", "Medium"),
        re.compile(r"\b[0-9a-f]{128}\b", re.IGNORECASE): ("SHA-512", "Low", "Low"),
        re.compile(r"\b[0-9a-f]{96}\b", re.IGNORECASE): ("SHA-384", "Low", "Low"),
        re.compile(r"\b[0-9a-f]{64}\b", re.IGNORECASE): ("SHA-256", "Low", "Low"),
        re.compile(r"\b[0-9a-f]{56}\b", re.IGNORECASE): ("SHA-224", "Low", "Low"),
        re.compile(r"\b[0-9a-f]{40}\b", re.IGNORECASE): ("SHA-1", "Low", "Low"),
        re.compile(r"(?<!jsessionid=)\b[0-9a-f]{32}\b", re.IGNORECASE): ("MD4 / MD5", "Low", "Low"),
    }

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for hash signatures in HTTP request and response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            # Combine request and response parts to search for hash patterns
            request_parts = [str(request.headers), str(request.data)]
            response_parts = [str(response.headers), response.text]
            parts_to_check = request_parts + response_parts

            for part in parts_to_check:
                if isinstance(part, (bytes, str)):  # Check if part is string or bytes-like
                    for pattern, (desc, risk, confidence) in self.hash_patterns.items():
                        
                        matches = pattern.findall(part)
                        for match in matches:
                            logger.debug(f"Found a match for hash type {desc}: {match}")
                            return Alert(risk_category=self.get_risk(risk), 
                                         confidence=self.get_confidence(confidence),
                                         description="Hash Disclosure",
                                         evidence=f"{desc} found: {match}", 
                                         msg_ref=self.MSG_REF,
                                         cwe_id=self.get_cwe_id(),
                                         wasc_id=self.get_wasc_id())
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def __str__(self) -> str:
        """
        Returns a string representation of the HashDisclosureScanRule object.

        Returns:
            str: A string representation of the HashDisclosureScanRule object.
        """
        return "Hash Disclosure Scan Rule"
    
    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 200 # CWE-200: Information Exposure

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 13 # WASC-13: Information Leakage
    
    def get_risk(self, str):
        if str == "High":
            return Risk.RISK_HIGH
        elif str == "Medium":
            return Risk.RISK_MEDIUM
        elif str == "Low":
            return Risk.RISK_LOW
        elif str == "Info":
            return Risk.RISK_INFO
        else:
            return False
        
    def get_confidence(self, str):
        if str == "High":
            return Confidence.CONFIDENCE_HIGH
        elif str == "Medium":
            return Confidence.CONFIDENCE_MEDIUM
        elif str == "Low":
            return Confidence.CONFIDENCE_LOW
        else:
            return False        
