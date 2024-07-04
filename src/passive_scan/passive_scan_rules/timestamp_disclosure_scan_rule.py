import logging
from requests.models import Request, Response
from datetime import datetime, timedelta
import re
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class TimestampDisclosureScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for timestamp disclosures in HTTP responses.
    """
    MSG_REF = "pscanrules.timestampdisclosure"
    RISK = Risk.RISK_LOW
    CONFIDENCE = Confidence.CONFIDENCE_LOW

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
        CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED
    ]

    EPOCH_Y2038 = 2147483647
    ZONED_NOW = datetime.now()

    RANGE_START = ZONED_NOW - timedelta(days=365 * 10)
    RANGE_STOP = min(EPOCH_Y2038, (ZONED_NOW + timedelta(days=365 * 10)).timestamp())
    ONE_YEAR_AGO = ZONED_NOW - timedelta(days=365)
    ONE_YEAR_FROM_NOW = ZONED_NOW + timedelta(days=365)

    TIMESTAMP_PATTERNS = {
        re.compile(r'\b(?:1\d|2[0-2])\d{8}\b(?!%)'): "Unix"
    }

    RESPONSE_HEADERS_TO_IGNORE = [
        'Keep-Alive', 'Cache-Control', 'ETag', 'Age', 
        'Strict-Transport-Security', 'Report-To', 'NEL', 
        'Expect-CT', 'RateLimit-Reset', 'X-RateLimit-Reset', 'X-Rate-Limit-Reset'
    ]

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for timestamp disclosures in the response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            headers = response.headers
            response_parts = [headers.get(header) for header in headers if header not in self.RESPONSE_HEADERS_TO_IGNORE]
            response_parts.append(response.text)

            for pattern, timestamp_type in self.TIMESTAMP_PATTERNS.items():
                logger.debug(f"Trying Timestamp Pattern: {pattern} for timestamp type {timestamp_type}")
                for part in response_parts:
                    if not part:
                        continue
                    matcher = pattern.finditer(part)
                    for match in matcher:
                        evidence = match.group()
                        try:
                            timestamp = datetime.utcfromtimestamp(int(evidence))
                        except ValueError:
                            continue
                        if not self.RANGE_START < timestamp < datetime.utcfromtimestamp(self.RANGE_STOP):
                            continue
                        if self.CONFIDENCE == Confidence.CONFIDENCE_HIGH:
                            found_instant = datetime.utcfromtimestamp(int(evidence))
                            if not (self.ONE_YEAR_AGO < found_instant < self.ONE_YEAR_FROM_NOW):
                                continue
                        return self.build_alert(timestamp_type, evidence, "", timestamp)
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)
    
    def build_alert(self, timestamp_type: str, evidence: str, param: str, timestamp: datetime) -> Alert:
        """
        Build an alert for the identified timestamp.

        Args:
            timestamp_type (str): The type of the timestamp.
            evidence (str): The evidence of the timestamp.
            param (str): The parameter where the timestamp was found.
            timestamp (datetime): The datetime object representing the timestamp.

        Returns:
            Alert: An Alert object.
        """
        formatted_date = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        extra_info = f"Timestamp found: {evidence} ({formatted_date})"
        return Alert(
            risk_category=self.RISK,
            confidence=self.CONFIDENCE,
            description=f"Timestamp disclosure detected - {timestamp_type}",
            msg_ref=self.MSG_REF,
            evidence=f"{evidence}, extra_info={extra_info}",
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id()
        )
    
    def __str__(self) -> str:
        """
        Returns a string representation of the TimestampDisclosureScanRule object.

        Returns:
            str: A string representation of the TimestampDisclosureScanRule object.
        """
        return "Timestamp Disclosure"
    
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
        return 13  # WASC-13: Info leakage
