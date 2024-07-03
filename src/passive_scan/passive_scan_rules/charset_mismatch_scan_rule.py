import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

# https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CharsetMismatchScanRule.java

class CharsetMismatchScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for charset mismatches between the HTTP response header and the body.
    """
    MSG_REF = "pscanrules.charsetmismatch"
    RISK = Risk.RISK_INFO
    CONFIDENCE = Confidence.CONFIDENCE_LOW

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for charset mismatches in the HTTP response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            # Get charset from the Content-Type header
            header_charset = response.headers.get('Content-Type', '').split('charset=')[-1].strip()
            if not header_charset:
                return NoAlert(msg_ref=self.MSG_REF)

            # Get the response content
            content = response.content.decode('utf-8', errors='ignore')

            # Check if the response is HTML
            if 'text/html' in response.headers.get('Content-Type', ''):
                # Find charset in <meta> tags
                meta_charset = self.extract_meta_charset(content)
                if meta_charset and meta_charset.lower() != header_charset.lower():
                    return self.raise_alert(header_charset, meta_charset)

            # Check if the response is XML
            if '<?xml' in content:
                xml_charset = self.extract_xml_charset(content)
                if xml_charset and xml_charset.lower() != header_charset.lower():
                    return self.raise_alert(header_charset, xml_charset)

            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def extract_meta_charset(self, content: str) -> str:
        """
        Extract the charset from the <meta> tags in HTML content.

        Args:
            content (str): The HTML content.

        Returns:
            str: The charset found in the <meta> tags, or an empty string if not found.
        """
        import re
        meta_charset_pattern = re.compile(r'<meta[^>]*charset=["\']?([^"\'>]*)["\']?', re.IGNORECASE)
        match = meta_charset_pattern.search(content)
        return match.group(1) if match else ''

    def extract_xml_charset(self, content: str) -> str:
        """
        Extract the charset from the XML declaration.

        Args:
            content (str): The XML content.

        Returns:
            str: The charset found in the XML declaration, or an empty string if not found.
        """
        import re
        xml_charset_pattern = re.compile(r'<\?xml[^>]*encoding=["\']([^"\'>]*)["\']', re.IGNORECASE)
        match = xml_charset_pattern.search(content)
        return match.group(1) if match else ''

    def raise_alert(self, header_charset: str, body_charset: str) -> Alert:
        """
        Raise an alert for a charset mismatch.

        Args:
            header_charset (str): The charset specified in the HTTP header.
            body_charset (str): The charset specified in the response body.

        Returns:
            Alert: An Alert object indicating the charset mismatch.
        """
        return Alert(
            risk_category=self.RISK,
            confidence=self.CONFIDENCE,
            msg_ref=self.MSG_REF,
            description="Charset mismatch",
            evidence=f"Charset mismatch: header={header_charset}, body={body_charset}",
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id()
        )

    def __str__(self) -> str:
        """
        Returns a string representation of the CharsetMismatchScanRule object.

        Returns:
            str: A string representation of the CharsetMismatchScanRule object.
        """
        return "Charset Mismatch Scan Rule"

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 436  # CWE-436: Interpretation Conflict

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 15  # WASC-15: Application Misconfiguration
