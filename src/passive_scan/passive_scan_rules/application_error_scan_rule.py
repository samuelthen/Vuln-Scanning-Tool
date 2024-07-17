import re
import logging
import xml.etree.ElementTree as ET
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class ApplicationErrorScanRule(BasePassiveScanRule):
    MSG_REF = "pscanrules.applicationerrors"
    RISK = Risk.RISK_MEDIUM
    CONFIDENCE = Confidence.CONFIDENCE_MEDIUM

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
        CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
        CommonAlertTag.WSTG_V42_ERRH_01_ERR,
        CommonAlertTag.WSTG_V42_ERRH_02_STACK
    ]

    APP_ERRORS_FILE = 'src/passive_scan/passive_scan_rules/utils/application_errors.xml'
    DEFAULT_ERRORS = []
    ERRORS_PAYLOAD_CATEGORY = "Application-Errors"

    def __init__(self):
        super().__init__()
        self.matcher = None
        self.payload_provider = lambda: self.DEFAULT_ERRORS
        self.load_content_matcher()

    def load_content_matcher(self):
        try:
            with open(self.APP_ERRORS_FILE, 'r') as f:
                content = f.read()
                self.matcher = self.ContentMatcher(self.parse_patterns_from_xml(content))
                logger.debug(f"Patterns loaded from XML: {self.matcher.patterns}")
        except (IOError, ValueError) as e:
            logger.warning(f"Unable to read {self.APP_ERRORS_FILE} input file: {e}. Falling back to default.")
            self.matcher = self.ContentMatcher(self.parse_patterns_from_xml(self.get_default_patterns()))
            logger.debug(f"Default patterns loaded: {self.matcher.patterns}")

    def parse_patterns_from_xml(self, xml_content):
        try:
            root = ET.fromstring(xml_content)
            patterns = [(pattern.text, pattern.get('type', 'string')) for pattern in root.findall(".//Pattern")]
            return patterns
        except ET.ParseError as e:
            logger.error(f"Error parsing XML: {e}")
            return []

    def get_default_patterns(self):
        return """
        <Patterns>
            <Pattern type="string">ERROR: parser: parse error at or near</Pattern>
        </Patterns>
        """

    class ContentMatcher:
        def __init__(self, patterns):
            self.patterns = []
            for pattern, pattern_type in patterns:
                try:
                    if pattern_type == 'regex':
                        re.compile(pattern)  # Validate regex pattern
                        self.patterns.append(pattern)
                    else:
                        # For string type, we escape special characters
                        escaped_pattern = re.escape(pattern)
                        self.patterns.append(escaped_pattern)
                except re.error as e:
                    logger.error(f"Invalid pattern skipped: {pattern}, error: {e}")

            logger.debug(f"ContentMatcher initialized with patterns: {self.patterns}")

        def find_in_content(self, content):
            for pattern in self.patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return pattern
            return None

    def check_risk(self, request: Request, response: Response) -> Alert:
        try:
            content_type = response.headers.get('Content-Type', '')
            logger.debug(f"Content-Type: {content_type}")
            if 'text/html' not in content_type and 'text/plain' not in content_type:
                return NoAlert(msg_ref=self.MSG_REF)

            body = response.text
            logger.debug(f"Response body: {body[:100]}...")  # Log only the first 100 characters

            if response.status_code == 500:
                return Alert(risk_category=self.RISK,
                             confidence=self.CONFIDENCE, 
                             description="Internal Server Error detected",
                             msg_ref=self.MSG_REF,
                             cwe_id=self.get_cwe_id(),
                             wasc_id=self.get_wasc_id())

            if response.status_code == 404 or 'application/wasm' in content_type:
                return NoAlert(msg_ref=self.MSG_REF)

            for payload in self.payload_provider():
                if payload in body:
                    return Alert(risk_category=self.RISK,
                                 confidence=self.CONFIDENCE, 
                                 description="Custom application error detected",
                                 msg_ref=self.MSG_REF,
                                 evidence=payload,
                                 cwe_id=self.get_cwe_id(), 
                                 wasc_id=self.get_wasc_id())

            evidence = self.matcher.find_in_content(body)
            if evidence:
                return Alert(risk_category=self.RISK,
                             confidence=self.CONFIDENCE,
                             description="Application error pattern detected",
                             msg_ref=self.MSG_REF,
                             evidence=evidence,
                             cwe_id=self.get_cwe_id(),
                             wasc_id=self.get_wasc_id())

            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            logger.error(f"Error during scan: {e}", exc_info=True)
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def __str__(self) -> str:
        return "Application Error"
    
    def get_cwe_id(self):
        return 200  # CWE-200: Information Exposure
    
    def get_wasc_id(self):
        return 13  # WASC-13: Information Leakage
