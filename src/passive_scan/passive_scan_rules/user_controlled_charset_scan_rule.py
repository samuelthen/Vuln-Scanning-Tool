import logging
import re
from requests.models import Request, Response
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class UserControlledCharsetScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check if user-controlled input is used to set the charset of the content.
    """
    MSG_REF = "pscanrules.usercontrolledcharset"
    RISK = Risk.RISK_INFO
    CONFIDENCE = Confidence.CONFIDENCE_LOW

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A03_INJECTION,
        CommonAlertTag.OWASP_2017_A01_INJECTION
    ]

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for user-controlled charset in the HTTP response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            params = self.get_url_parameters(request.url)
            
            if not params:
                return NoAlert(msg_ref=self.MSG_REF)

            content_type = response.headers.get("Content-Type")
            if content_type and self.check_content_type_charset(content_type, params):
                return self.create_alert("Content-Type HTTP header", "charset", content_type)

            response_body = response.text
            if not response_body:
                return NoAlert(msg_ref=self.MSG_REF)

            if "text/html" in content_type or "application/xhtml+xml" in content_type:
                if self.check_meta_content_charset(response_body, params):
                    return self.create_alert("META", "Content-Type", response_body)
                
            elif "application/xml" in content_type:
                if self.check_xml_encoding_charset(response_body, params):
                    return self.create_alert("XML Declaration", "encoding", response_body)

            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def get_url_parameters(self, url):
        # Parse the URL
        parsed_url = urlparse(url)
        # Extract query parameters
        query_params = parse_qs(parsed_url.query)
        # Simplify parameters to single values
        return {k: v[0] for k, v in query_params.items()}

    def check_meta_content_charset(self, response_body: str, params: dict) -> bool:
        """
        Check if the META tag's charset is controlled by user input.

        Args:
            response_body (str): The HTTP response body.
            params (dict): The HTTP request parameters.

        Returns:
            bool: True if user-controlled charset is found, False otherwise.
        """
        soup = BeautifulSoup(response_body, 'html.parser')
        meta_tags = soup.find_all('meta', attrs={'http-equiv': 'Content-Type'})
        for meta_tag in meta_tags:
            content = meta_tag.get('content', '')
            charset = self.get_charset_from_content(content)
            if charset and self.is_user_controlled_charset(charset, params):
                return True
        return False

    def get_charset_from_content(self, content: str) -> str:
        """
        Extract charset from the content attribute of a META tag.

        Args:
            content (str): The content attribute of a META tag.

        Returns:
            str: The extracted charset, or None if not found.
        """
        try:
            if 'charset=' in content:
                parts = content.split('charset=')
                charset = parts[-1].split(';')[0].strip()
                return charset
        except Exception as e:
            logger.error(f"Error extracting charset from content: {e}")
        return None

    def check_xml_encoding_charset(self, response_body: str, params: dict) -> bool:
        """
        Check if the XML declaration's encoding is controlled by user input.

        Args:
            response_body (str): The HTTP response body.
            params (dict): The HTTP request parameters.

        Returns:
            bool: True if user-controlled encoding is found, False otherwise.
        """
        try:
            # Extract the encoding from the XML declaration using a regular expression
            match = re.search(r'<\?xml[^>]*encoding=["\']([^"\']+)["\']', response_body)
            if match:
                encoding = match.group(1)
                if encoding and self.is_user_controlled_charset(encoding, params):
                    return True
        except Exception as e:
            logger.error(f"Error during XML encoding check: {e}")
        return False
    
    def is_user_controlled_charset(self, charset: str, params: dict) -> bool:
        """
        Check if the charset is controlled by user input.

        Args:
            charset (str): The charset to check.
            params (dict): The HTTP request parameters.

        Returns:
            bool: True if the charset is controlled by user input, False otherwise.
        """
        charset = charset.lower()
        for param in params.values():
            if charset == param.lower():
                return True
        return False

    def check_content_type_charset(self, content_type: str, params: dict) -> bool:
        """
        Check if the Content-Type charset is controlled by user input.

        Args:
            content_type (str): The Content-Type header value.
            params (dict): The HTTP request parameters.

        Returns:
            bool: True if user-controlled charset is found, False otherwise.
        """
        if 'charset=' in content_type:
            charset = content_type.split('charset=')[-1].split(';')[0].strip()
            return self.is_user_controlled_charset(charset, params)
        return False

    def create_alert(self, tag: str, attr: str, value: str) -> Alert:
        """
        Create an alert based on the detected issue.

        Args:
            tag (str): The tag where the issue was found.
            attr (str): The attribute where the issue was found.
            value (str): The detected value.

        Returns:
            Alert: The constructed Alert object.
        """
        return Alert(
            risk_category=self.RISK,
            confidence=self.CONFIDENCE,
            description="User-controlled charset detected, possible security risk.",
            msg_ref=self.MSG_REF,
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id(),
            evidence=f"{value}. Tag: {tag}, Attribute: {attr}, Value: {value}"
        )

    def __str__(self) -> str:
        """
        Returns a string representation of the UserControlledCharsetScanRule object.

        Returns:
            str: A string representation of the UserControlledCharsetScanRule object.
        """
        return "User-Controlled Charset Scan Rule"

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 20  # CWE-20: Improper Input Validation

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 20  # WASC-20: Improper Input Handling
