import logging
import re
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class InfoPrivateAddressDisclosureScanRule(BasePassiveScanRule):
    MSG_REF = "pscanrules.infoprivateaddressdisclosure"
    RISK = Risk.RISK_LOW
    CONFIDENCE = Confidence.CONFIDENCE_MEDIUM

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
        CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED,
    ]

    REGULAR_IP_OCTET = r"(25[0-5]|2[0-4]\d|[01]?\d{1,2})"
    NOT_FOLLOWED_BY_ANOTHER_DOTTED_NUMBER = r"\b(?!\.\d)"
    NOT_FOLLOWED_BY_ANOTHER_DASHED_NUMBER = r"\b(?!-\d)"
    NOT_PRECEDED_BY_ANOTHER_DOTTED_NUMBER = r"(?<!\d\.)\b"
    PRECEDED_BY_IP_DASH = r"\bip-"

    patternPrivateIP = re.compile(
        rf"("
        rf"{NOT_PRECEDED_BY_ANOTHER_DOTTED_NUMBER}10\.{REGULAR_IP_OCTET}\.{REGULAR_IP_OCTET}\.{REGULAR_IP_OCTET}{NOT_FOLLOWED_BY_ANOTHER_DOTTED_NUMBER}"
        rf"|{NOT_PRECEDED_BY_ANOTHER_DOTTED_NUMBER}172\.(3[01]|2\d|1[6-9])\.{REGULAR_IP_OCTET}\.{REGULAR_IP_OCTET}{NOT_FOLLOWED_BY_ANOTHER_DOTTED_NUMBER}"
        rf"|{NOT_PRECEDED_BY_ANOTHER_DOTTED_NUMBER}192\.168\.{REGULAR_IP_OCTET}\.{REGULAR_IP_OCTET}{NOT_FOLLOWED_BY_ANOTHER_DOTTED_NUMBER}"
        rf"|{PRECEDED_BY_IP_DASH}10-{REGULAR_IP_OCTET}-{REGULAR_IP_OCTET}-{REGULAR_IP_OCTET}{NOT_FOLLOWED_BY_ANOTHER_DOTTED_NUMBER}"
        rf"|{PRECEDED_BY_IP_DASH}172-(3[01]|2\d|1[6-9])-{REGULAR_IP_OCTET}-{REGULAR_IP_OCTET}{NOT_FOLLOWED_BY_ANOTHER_DASHED_NUMBER}"
        rf"|{PRECEDED_BY_IP_DASH}192-168-{REGULAR_IP_OCTET}-{REGULAR_IP_OCTET}{NOT_FOLLOWED_BY_ANOTHER_DASHED_NUMBER}"
        rf")"
        rf"(:(0|[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65([0-4]\d{2}|5[0-2]\d|53[0-5]))\b)?",
        re.MULTILINE
    )

    def check_risk(self, request: Request, response: Response) -> Alert:
        try:
            host = request.headers.get('Host')
            body = response.text
            matcher = self.patternPrivateIP.finditer(body)
            sbTxtFound = []

            for match in matcher:
                if match.group() == host:
                    continue
                sbTxtFound.append(match.group())

            if sbTxtFound:
                return Alert(
                    risk_category=self.RISK,
                    confidence=self.CONFIDENCE,
                    description="Private IP address disclosure detected",
                    msg_ref=self.MSG_REF,
                    evidence="\n".join(sbTxtFound),
                    cwe_id=self.get_cwe_id(),
                    wasc_id=self.get_wasc_id()
                )
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def __str__(self) -> str:
        return "Private IP Address Disclosure"

    def get_cwe_id(self):
        return 200  # CWE-200: Information Exposure

    def get_wasc_id(self):
        return 13  # WASC-13: Info leakage