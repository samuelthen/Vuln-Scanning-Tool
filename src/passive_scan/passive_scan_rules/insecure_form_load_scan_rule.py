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
        Check for insecure form load over HTTP.

        Returns:
        - Alert if an insecure form load is detected.
        - NoAlert if no issues are found.
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
        """
        content_type = response.headers.get("Content-Type", "")
        return "text/html" in content_type or "application/xhtml+xml" in content_type or "application/xhtml" in content_type

    def __str__(self) -> str:
        return "Insecure Form Load Scan Rule"

    def get_cwe_id(self) -> int:
        return 319  # CWE-319: Cleartext Transmission of Sensitive Information

    def get_wasc_id(self) -> int:
        return 15  # WASC-15: Application Misconfiguration
