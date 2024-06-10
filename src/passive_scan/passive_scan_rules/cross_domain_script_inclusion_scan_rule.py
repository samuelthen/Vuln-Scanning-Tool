from urllib.parse import urlparse
from bs4 import BeautifulSoup
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule

class CrossDomainScriptInclusionScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for cross-domain script inclusions without the integrity attribute.
    """
    def is_script_from_other_domain(self, request_host, script_url):
        """
        Check if a script URL is from a different domain than the request domain.

        Args:
        - request_host (str): The domain of the request URL.
        - script_url (str): The URL of the script.

        Returns:
        - bool: True if the script is from a different domain, False otherwise.
        """
        try:
            parsed_script_url = urlparse(script_url)
            if not parsed_script_url.netloc:
                # Relative URL, assume it's from the same domain
                return False

            script_host = parsed_script_url.netloc
            return script_host.lower() != request_host.lower()
        except Exception as e:
            # Handle any exceptions that occur during URL parsing
            print(f"Error parsing script URL: {e}")
            return False

    def check_risk(self, request: Request, response: Response):
        """
        Check for cross-domain script inclusions without the integrity attribute.

        Returns:
        - str: A message indicating the risk level and any evidence found.
        """
        try:
            # Parse request and response
            request_url = request.url
            request_host = urlparse(request_url).netloc
            response_body = response.text
            response_headers = response.headers

            if "Content-Type" in response_headers and "text/html" in response_headers["Content-Type"]:
                soup = BeautifulSoup(response_body, 'html.parser')
                scripts = soup.find_all('script', src=True)

                risk_flag = False
                evidence = []

                for script in scripts:
                    script_src = script['src']
                    if self.is_script_from_other_domain(request_host, script_src):
                        integrity = script.get('integrity')
                        if not integrity or not integrity.strip():
                            risk_flag = True
                            evidence.append(str(script))
                
                if risk_flag:
                    return f"Low risk (Cross Domain Script Inclusion detected without integrity attribute). Evidence: {evidence}"
                else:
                    return 'No risk (no cross-domain scripts without integrity attribute found)'

            return 'No risk (not an HTML response)'
        except Exception as e:
            # Handle any exceptions that occur during the scan
            print(f"Error during scan: {e}")
            return 'Error occurred during scan, check logs for details'
        
    def __str__(self) -> str:
        return "Cross Domain Script Inclusion"