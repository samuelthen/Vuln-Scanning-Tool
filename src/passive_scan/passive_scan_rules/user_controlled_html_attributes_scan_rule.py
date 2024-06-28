import logging
from requests.models import Request, Response
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class UserControlledHTMLAttributesScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for user-controlled HTML attributes.
    """
    MSG_REF = "pscanrules.usercontrolledhtmlattributes"
    RISK = Risk.RISK_INFO
    CONFIDENCE = Confidence.CONFIDENCE_LOW

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A03_INJECTION,
        CommonAlertTag.OWASP_2017_A01_INJECTION
    ]
    
    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for user-controlled HTML attributes in the response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            if "Content-Type" in response.headers and "text/html" in response.headers["Content-Type"]:
                # Parse the HTML response
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Collect all form and URL parameters
                params = self.get_parameters(request.url)
                
                for element in soup.find_all(True):
                    for attr, value in element.attrs.items():
                        for param in params:
                            if param in value:
                                if self.is_potentially_harmful(value, param):
                                    evidence = f"Element: {element.name}\n" \
                                               f"Attribute: {attr}\n" \
                                               f"Attribute Value: {value}\n" \
                                               f"Parameter: {param}"
                                    return Alert(risk_category=self.RISK,
                                                 confidence=self.CONFIDENCE,
                                                 description="User-controlled HTML attribute detected.",
                                                 msg_ref=self.MSG_REF,
                                                 evidence=evidence,
                                                 cwe_id=self.get_cwe_id(),
                                                 wasc_id=self.get_wasc_id())
                
                return NoAlert(msg_ref=self.MSG_REF)
            
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)
    
    def get_parameters(self, url: str) -> set:
        """
        Extract parameters from the URL.

        Args:
            url (str): The URL to extract parameters from.
        
        Returns:
            set: A set of parameter values.
        """
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        params = set()
        for param_list in query_params.values():
            params.update(param_list)
        return params
    
    def is_potentially_harmful(self, value: str, param: str) -> bool:
        """
        Determine if the attribute value is potentially harmful.

        Args:
            value (str): The attribute value.
            param (str): The parameter value to check against.

        Returns:
            bool: True if potentially harmful, False otherwise.
        """
        # Check for protocol and domain control
        parsed_url = urlparse(value)
        if parsed_url.scheme and parsed_url.netloc:
            if param in parsed_url.scheme or param in parsed_url.netloc:
                return True
        
        # Check if the attribute value starts with the user-controlled parameter
        if value.lower().startswith(param.lower()):
            return True
        
        return False
    
    def __str__(self) -> str:
        """
        Returns a string representation of the UserControlledHTMLAttributesScanRule object.

        Returns:
            str: A string representation of the UserControlledHTMLAttributesScanRule object.
        """
        return "User-Controlled HTML Attribute"

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 20 # CWE-20: Improper Input Validation
    
    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 20 # WASC-20: Improper Input Handling
