import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class MixedContentScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for mixed content in HTTPS responses.
    """
    
    MSG_REF = "pscanrules.mixedcontent"

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
        CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
        CommonAlertTag.WSTG_V42_CRYP_03_CRYPTO_FAIL
    ]

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for mixed content in the HTTP response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            # Check if the request was made over HTTPS
            if request.url.startswith("https://"):
                # Check if the response is HTML
                if "Content-Type" in response.headers and "text/html" in response.headers["Content-Type"]:
                    mixed_content = []
                    inc_script = False
                    # Parse the HTML content
                    source = self.parse_html(response.text)
                    for element in source:
                        if self.add_atts_containing_http_content(element, "src", mixed_content):
                            if element.name == "script":
                                inc_script = True
                        self.add_atts_containing_http_content(element, "background", mixed_content)
                        self.add_atts_containing_http_content(element, "classid", mixed_content)
                        self.add_atts_containing_http_content(element, "codebase", mixed_content)
                        self.add_atts_containing_http_content(element, "data", mixed_content)
                        self.add_atts_containing_http_content(element, "icon", mixed_content)
                        self.add_atts_containing_http_content(element, "usemap", mixed_content)
                        
                        self.add_atts_containing_http_content(element, "action", mixed_content)
                        self.add_atts_containing_http_content(element, "formaction", mixed_content)

                    if mixed_content:
                        details = "\n".join([f"tag={mc['tag']} {mc['att']}={mc['value']}" for mc in mixed_content])
                        return self.build_alert(mixed_content[0]['value'], details, inc_script)

            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def add_atts_containing_http_content(self, element, attribute, mixed_content):
        """
        Check if the element contains an attribute with HTTP content.

        Args:
            element (Element): The HTML element.
            attribute (str): The attribute to check.
            mixed_content (list): The list to add mixed content details.

        Returns:
            bool: True if mixed content is found, False otherwise.
        """
        val = element.get(attribute)
        if val and val.lower().startswith("http:"):
            mixed_content.append({'tag': element.name, 'att': attribute, 'value': val})
            return True
        return False

    def build_alert(self, first, all_details, inc_script):
        """
        Build an alert based on the mixed content details.

        Args:
            first (str): The first occurrence of mixed content.
            all_details (str): All mixed content details.
            inc_script (bool): Indicates if script content was found.

        Returns:
            Alert: The constructed Alert object.
        """
        risk = Risk.RISK_LOW
        if inc_script:
            risk = Risk.RISK_MEDIUM
        return Alert(
            risk_category=risk,
            confidence=Confidence.CONFIDENCE_MEDIUM,
            description="Mixed content detected in HTTPS page.",
            msg_ref=self.MSG_REF,
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id(),
            evidence=f"{first}" # . Details: {all_details}
        )

    def parse_html(self, html_content):
        """
        Parse HTML content.

        Args:
            html_content (str): The HTML content to parse.

        Returns:
            list: A list of parsed HTML elements.
        """
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')
        return soup.find_all()

    def __str__(self) -> str:
        """
        Returns a string representation of the MixedContentScanRule object.

        Returns:
            str: A string representation of the MixedContentScanRule object.
        """
        return "Mixed Content"

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 311  # CWE-311: Missing Encryption of Sensitive Data

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 4  # WASC-4: Insufficient Transport Layer Protection
