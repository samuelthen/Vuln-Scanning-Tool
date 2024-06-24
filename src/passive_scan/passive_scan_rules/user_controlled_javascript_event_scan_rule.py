import logging
from requests.models import Request, Response
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError

logger = logging.getLogger(__name__)

class UserControlledJavascriptEventScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for user-controlled JavaScript events.
    """
    
    # List of JavaScript event attributes to check for
    JAVASCRIPT_EVENTS = [
        "onabort", "onbeforeunload", "onblur", "onchange", "onclick", 
        "oncontextmenu", "ondblclick", "ondrag", "ondragend", "ondragenter", 
        "ondragleave", "ondragover", "ondragstart", "ondrop", "onerror", 
        "onfocus", "onhashchange", "onkeydown", "onkeypress", "onkeyup", 
        "onload", "onmessage", "onmousedown", "onmousemove", "onmouseout", 
        "onmouseover", "onmouseup", "onmousewheel", "onoffline", "ononline", 
        "onpopstate", "onreset", "onresize", "onscroll", "onselect", 
        "onstorage", "onsubmit", "onunload"
    ]
    
    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for user-controlled JavaScript events in the response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            # Check if the response is HTML
            if "Content-Type" in response.headers and "text/html" in response.headers["Content-Type"]:
                # Parse the HTML response
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Collect all form and URL parameters
                params = self.get_parameters(request.url)
                
                # Check each HTML element and its attributes
                for element in soup.find_all(True):
                    for attr, value in element.attrs.items():
                        if attr.lower() in self.JAVASCRIPT_EVENTS:
                            for param in params:
                                if param in value:
                                    evidence = f"Element: {element.name}\n" \
                                               f"Attribute: {attr}\n" \
                                               f"Attribute Value: {value}\n" \
                                               f"Parameter: {param}"
                                    return Alert(risk_category="Informational",
                                                 description="User-controlled JavaScript event detected.",
                                                 msg_ref="pscanrules.usercontrolledjavascriptevent",
                                                 evidence=evidence,
                                                 cwe_id=self.get_cwe_id(),
                                                 wasc_id=self.get_wasc_id())                        
                return NoAlert()
            
            return NoAlert()
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e))
    
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
    
    def __str__(self) -> str:
        """
        Returns a string representation of the UserControlledJavascriptEventScanRule object.

        Returns:
            str: A string representation of the UserControlledJavascriptEventScanRule object.
        """
        return "User-Controlled JavaScript Event"

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
