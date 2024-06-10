from requests.models import Request, Response
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
from .utils.base_passive_scan_rule import BasePassiveScanRule

class UserControlledHTMLAttributesScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for user-controlled HTML attributes.
    """
    
    def check_risk(self, request: Request, response: Response) -> str:
        """
        Check for user-controlled HTML attributes in the response.

        Returns:
        - str: A message indicating the risk level.
        """
        try:
            if "Content-Type" in response.headers and "text/html" in response.headers["Content-Type"]:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Collect all form and URL parameters
                params = self.get_parameters(request.url)
                
                for element in soup.find_all(True):
                    for attr, value in element.attrs.items():
                        for param in params:
                            if param in value:
                                if self.is_potentially_harmful(value, param):
                                    return self.build_alert(request.url, element.name, attr, value, param)
                
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
    
    def is_potentially_harmful(self, value: str, param: str) -> bool:
        """
        Determine if the attribute value is potentially harmful.

        Returns:
        - bool: True if potentially harmful, False otherwise.
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
    
    def build_alert(self, url: str, element_name: str, attribute: str, attribute_value: str, param: str) -> str:
        """
        Build an alert message.

        Returns:
        - str: The alert message with the risk level and evidence.
        """
        evidence = f"Element: {element_name}\nAttribute: {attribute}\nAttribute Value: {attribute_value}\nParameter: {param}"
        return f"High risk (potential XSS vulnerability): User-controlled HTML attribute detected. {evidence}"
    
    def __str__(self) -> str:
        return "User-Controlled HTML Attribute"
