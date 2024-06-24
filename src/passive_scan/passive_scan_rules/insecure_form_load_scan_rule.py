import logging
from requests.models import Request, Response
from bs4 import BeautifulSoup
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError

logger = logging.getLogger(__name__)

class InsecureFormLoadScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for forms loading over insecure HTTP connections.
    """

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for forms loading over insecure HTTP connections.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            # Check if the response is HTML
            if not self.is_response_html(response):
                return NoAlert()
            
            # Check if the request is already HTTPS
            if request.url.lower().startswith("https://"):
                return NoAlert()
            
            # Parse the HTML response
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                form_action = form.get('action')
                # Check if form action uses HTTPS while the page is served over HTTP
                if form_action and form_action.strip().lower().startswith("https://"):
                    evidence = str(form)
                    return Alert(risk_category="Medium",
                                 description="Form action uses HTTPS while the page is served over HTTP",
                                 msg_ref="pscanrules.insecureformload",
                                 cwe_id=self.get_cwe_id(),
                                 wasc_id=self.get_wasc_id(),
                                 evidence=evidence)

            return NoAlert()
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e))

    def is_response_html(self, response: Response) -> bool:
        """
        Check if the response content type is HTML.

        Args:
            response (Response): The HTTP response object.

        Returns:
            bool: True if the response content type is HTML, False otherwise.
        """
        content_type = response.headers.get("Content-Type", "")
        return "text/html" in content_type or "application/xhtml+xml" in content_type or "application/xhtml" in content_type

    def __str__(self) -> str:
        """
        Returns a string representation of the InsecureFormLoadScanRule object.

        Returns:
            str: A string representation of the InsecureFormLoadScanRule object.
        """
        return "Insecure Form Load Scan Rule"

    def get_cwe_id(self) -> int:
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 319  # CWE-319: Cleartext Transmission of Sensitive Information

    def get_wasc_id(self) -> int:
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 15  # WASC-15: Application Misconfiguration
