import logging
import base64
import zlib
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class InsecureJsfViewStatePassiveScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for insecure JSF ViewState.
    """

    MSG_REF = "pscanrules.insecurejsfviewstate"
    RISK = Risk.RISK_MEDIUM
    CONFIDENCE = Confidence.CONFIDENCE_LOW

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN,
        CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG
    ]

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for insecure JSF ViewState in the HTTP response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            if response.content and response.headers.get("Content-Type", "").startswith("text/html"):
                source_elements = self.extract_input_elements(response.text)

                for element in source_elements:
                    element_id = element.get("id", "")
                    if element_id and "javax.faces.ViewState".lower() in element_id.lower():
                        view_state = element.get("value")
                        if view_state and not view_state.startswith("_") and not self.is_view_state_stored_on_server(view_state):
                            if not self.is_view_state_secure(view_state):
                                return Alert(risk_category=Risk.RISK_MEDIUM,
                                             confidence=Confidence.CONFIDENCE_LOW, 
                                             description="Insecure JSF ViewState detected",
                                             msg_ref=self.MSG_REF,
                                             evidence=view_state,
                                             cwe_id=self.get_cwe_id(), 
                                             wasc_id=self.get_wasc_id())
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e),msg_ref=self.MSG_REF)

    def extract_input_elements(self, html):
        """
        Extract input elements from the HTML content.

        Args:
            html (str): The HTML content.

        Returns:
            list: A list of dictionaries representing the input elements.
        """
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, 'html.parser')
        return [{'id': input_element.get('id'), 'value': input_element.get('value')} for input_element in soup.find_all('input')]

    def is_view_state_secure(self, view_state: str) -> bool:
        """
        Checks whether the specified viewState is secure or possibly not.

        Args:
            view_state (str): The view state string.

        Returns:
            bool: True if the viewState is cryptographically secure, and False otherwise.
        """
        if not view_state:
            return True
        
        try:
            decoded_bytes = base64.b64decode(view_state)
            decompressed_bytes = self.decompress(decoded_bytes)
            decoded_view_state = decompressed_bytes.decode('utf-8')
            
            return self.is_raw_view_state_secure(decoded_view_state)
        except (base64.binascii.Error, zlib.error, UnicodeDecodeError):
            return self.is_raw_view_state_secure(view_state)

    def decompress(self, value: bytes) -> bytes:
        """
        Decompress the byte array if it is compressed.

        Args:
            value (bytes): The byte array to decompress.

        Returns:
            bytes: The decompressed byte array.
        """
        if len(value) < 4:
            return value
        if value[:2] != b'\x1f\x8b':  # GZIP magic number
            return value
        return zlib.decompress(value, 16 + zlib.MAX_WBITS)

    def is_raw_view_state_secure(self, view_state: str) -> bool:
        """
        Check if the raw ViewState string is secure.

        Args:
            view_state (str): The raw ViewState string.

        Returns:
            bool: True if secure, False otherwise.
        """
        return "java" not in view_state.lower()

    def is_view_state_stored_on_server(self, val: str) -> bool:
        """
        Determine if the ViewState is stored on the server.

        Args:
            val (str): The ViewState value.

        Returns:
            bool: True if stored on the server, False otherwise.
        """
        return ':' in val

    def __str__(self) -> str:
        """
        Returns a string representation of the InsecureJsfViewStatePassiveScanRule object.

        Returns:
            str: A string representation of the InsecureJsfViewStatePassiveScanRule object.
        """
        return "Insecure JSF ViewState Scan Rule"

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 642  # CWE-642: External Control of Critical State Data

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 14  # WASC-14: Server Misconfiguration
