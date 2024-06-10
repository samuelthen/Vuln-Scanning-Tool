from requests.models import Request, Response
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
from .utils.base_passive_scan_rule import BasePassiveScanRule

class UserControlledJavascriptEventScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for user-controlled JavaScript events.
    """
    
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
    
    def check_risk(self, request: Request, response: Response) -> str:
        """
        Check for user-controlled JavaScript events in the response.

        Returns:
        - str: A message indicating the risk level.
        """
        try:
            if "Content-Type" in response.headers and "text/html" in response.headers["Content-Type"]:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Collect all form and URL parameters
                params = self.get_parameters(request.url)
                
                # Check each HTML element and its attributes
                for element in soup.find_all(True):
                    for attr, value in element.attrs.items():
                        if attr.lower() in self.JAVASCRIPT_EVENTS:
                            for param in params:
                                if param in value:
                                    return self.build_alert(request.url, attr, value, param)
                
                return "No risk detected"
            
            return "No risk (not an HTML response)"
        except Exception as e:
            # Handle any exceptions that occur during the scan
            print(f"Error during scan: {e}")
            return 'Error occurred during scan, check logs for details'
    
    def get_parameters(self, url: str) -> set:
        """
        Extract parameters from the URL.
        
        Returns:
        - set: A set of parameter values.
        """
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        params = set()
        for param_list in query_params.values():
            params.update(param_list)
        return params
    
    def build_alert(self, url: str, attribute: str, attribute_value: str, param: str) -> str:
        """
        Build an alert message.

        Returns:
        - str: The alert message with the risk level and evidence.
        """
        evidence = f"Attribute: {attribute}\nAttribute Value: {attribute_value}\nParameter: {param}"
        return f"High risk (potential XSS vulnerability): User-controlled JavaScript event detected. {evidence}"
    
    def __str__(self) -> str:
        return "User-Controlled JavaScript Event"

