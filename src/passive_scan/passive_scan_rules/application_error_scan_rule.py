import re
import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError

logger = logging.getLogger(__name__)

class ApplicationErrorScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for application error messages in HTTP responses.
    """

    # Path to the XML file containing error patterns
    APP_ERRORS_FILE = 'src/passive_scan/passive_scan_rules/utils/application_errors.xml'
    DEFAULT_ERRORS = []
    ERRORS_PAYLOAD_CATEGORY = "Application-Errors"

    def __init__(self):
        """
        Initialize the ApplicationErrorScanRule with default settings.
        """
        super().__init__()
        self.matcher = None
        self.payload_provider = lambda: self.DEFAULT_ERRORS
        self.load_content_matcher()

    def load_content_matcher(self):
        """
        Load the content matcher with patterns from an external file.
        """
        try:
            with open(self.APP_ERRORS_FILE, 'r') as f:
                self.matcher = self.ContentMatcher(f.read())
        except (IOError, ValueError) as e:
            logger.warning(f"Unable to read {self.APP_ERRORS_FILE} input file: {e}. Falling back to default.")
            self.matcher = self.ContentMatcher(self.get_default_patterns())

    def get_default_patterns(self):
        """
        Fallback method to get default patterns if the external file is not accessible.

        Returns:
            str: A string containing default error patterns.
        """
        return """
        <patterns>
            <!-- Add default error patterns here -->
            <pattern>ERROR: parser: parse error at or near</pattern>
        </patterns>
        """

    class ContentMatcher:
        """
        Inner class to handle content matching with patterns.
        """
        def __init__(self, patterns):
            """
            Initialize the ContentMatcher with patterns.

            Args:
                patterns (str): A string containing error patterns.
            """
            self.patterns = re.findall(r'<pattern>(.*?)</pattern>', patterns, re.DOTALL)

        def find_in_content(self, content):
            """
            Find matching patterns in the content.

            Args:
                content (str): The content to search patterns in.

            Returns:
                str: The first matching pattern found, or None if no match is found.
            """
            for pattern in self.patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return pattern
            return None

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Perform the passive scanning of application errors inside the response content.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            # Skip non-HTML or non-plaintext responses
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' not in content_type and 'text/plain' not in content_type:
                return NoAlert()

            body = response.text

            # Check for INTERNAL SERVER ERROR
            if response.status_code == 500:
                return Alert(risk_category="Low", 
                             description="Internal Server Error detected",
                             msg_ref="pscanrules.applicationerrors",
                             cwe_id=self.get_cwe_id(),
                             wasc_id=self.get_wasc_id())

            # Skip 404 and wasm responses
            if response.status_code == 404 or 'application/wasm' in content_type:
                return NoAlert()

            # Check for custom payloads
            for payload in self.payload_provider():
                if payload in body:
                    return Alert(risk_category="Medium", 
                                 description="Custom application error detected",
                                 msg_ref="pscanrules.applicationerrors",
                                 evidence=payload,
                                 cwe_id=self.get_cwe_id(), 
                                 wasc_id=self.get_wasc_id())

            # Check for patterns in content
            evidence = self.matcher.find_in_content(body)
            if evidence:
                return Alert(risk_category="Medium",
                             description="Application error pattern detected",
                             msg_ref="pscanrules.applicationerrors",
                             evidence=evidence,
                             cwe_id=self.get_cwe_id(),
                             wasc_id=self.get_wasc_id())

            return NoAlert()
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e))

    def __str__(self) -> str:
        """
        Returns a string representation of the ApplicationErrorScanRule object.

        Returns:
            str: A string representation of the ApplicationErrorScanRule object.
        """
        return "Application Error"
    
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
