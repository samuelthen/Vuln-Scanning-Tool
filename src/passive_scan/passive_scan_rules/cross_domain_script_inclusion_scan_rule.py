import logging
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class CrossDomainScriptInclusionScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for cross-domain script inclusions without the integrity attribute.
    """
    MSG_REF = "pscanrules.crossdomainscriptinclusion"
    RISK = Risk.RISK_LOW
    CONFIDENCE = Confidence.CONFIDENCE_MEDIUM

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A08_INTEGRITY_FAIL
    ]
    
    def is_script_from_other_domain(self, request_host, script_url):
        """
        Check if a script URL is from a different domain than the request domain.

        Args:
            request_host (str): The domain of the request URL.
            script_url (str): The URL of the script.

        Returns:
            bool: True if the script is from a different domain, False otherwise.
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
            logging.error(f"Error parsing script URL: {e}")
            return False

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for cross-domain script inclusions without the integrity attribute.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            # Parse request and response
            request_url = request.url
            request_host = urlparse(request_url).netloc
            response_body = response.text
            response_headers = response.headers

            if "Content-Type" in response_headers and "text/html" in response_headers["Content-Type"]:
                # Parse the HTML response
                soup = BeautifulSoup(response_body, 'html.parser')
                scripts = soup.find_all('script', src=True)

                risk_flag = False
                evidence = []

                # Check each script tag
                for script in scripts:
                    script_src = script['src']
                    if self.is_script_from_other_domain(request_host, script_src):
                        integrity = script.get('integrity')
                        if not integrity or not integrity.strip():
                            risk_flag = True
                            evidence.append(str(script))
                
                if risk_flag:
                    return Alert(risk_category=self.RISK,
                                 confidence=self.CONFIDENCE, 
                                 description="Cross Domain Script Inclusion detected without integrity attribute)",
                                 msg_ref=self.MSG_REF,
                                 evidence=evidence,
                                 cwe_id=self.get_cwe_id(),
                                 wasc_id=self.get_wasc_id())
                else:
                    return NoAlert(msg_ref=self.MSG_REF)

            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)
        
    def __str__(self) -> str:
        """
        Returns a string representation of the CrossDomainScriptInclusionScanRule object.

        Returns:
            str: A string representation of the CrossDomainScriptInclusionScanRule object.
        """
        return "Cross Domain Script Inclusion"
    
    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 829 # CWE-829: Inclusion of Functionality from Untrusted Control Sphere
    
    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 15 # WASC-15: Application Misconfiguration
