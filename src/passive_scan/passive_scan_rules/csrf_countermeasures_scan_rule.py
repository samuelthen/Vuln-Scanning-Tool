import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class CsrfCountermeasuresScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for CSRF countermeasures in HTML forms.
    """
    MSG_REF = "pscanrules.noanticsrftokens"
    RISK = Risk.RISK_MEDIUM
    CONFIDENCE = Confidence.CONFIDENCE_LOW

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
        CommonAlertTag.OWASP_2017_A05_BROKEN_AC,
        CommonAlertTag.WSTG_V42_SESS_05_CSRF
    ]

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for the presence of CSRF countermeasures in HTML forms.

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
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
                
                forms = soup.find_all('form')
                if not forms:
                    return NoAlert(msg_ref=self.MSG_REF)

                # List of CSRF token names to check for
                csrf_tokens = ["csrf_token", "csrf", "xsrf_token", "X-CSRF-Token"]
                ignore_list = self.get_csrf_ignore_list()
                ignore_att_name = self.get_csrf_ignore_att_name()
                ignore_att_value = self.get_csrf_ignore_att_value()

                for form in forms:
                    # Check if the form is in the ignore list
                    if self.form_on_ignore_list(form, ignore_list):
                        continue

                    has_csrf_token = False
                    inputs = form.find_all('input')
                    for input_tag in inputs:
                        if input_tag.get('name') in csrf_tokens or input_tag.get('id') in csrf_tokens:
                            has_csrf_token = True
                            break

                    # Check for security annotations if specified
                    if ignore_att_name and form.get(ignore_att_name) == ignore_att_value:
                        has_csrf_token = True

                    if not has_csrf_token:
                        evidence = str(form)
                        return Alert(risk_category=self.RISK,
                                     confidence=self.CONFIDENCE, 
                                     description="Form without CSRF countermeasures", 
                                     msg_ref=self.MSG_REF, 
                                     cwe_id=self.get_cwe_id(), 
                                     wasc_id=self.get_wasc_id(), 
                                     evidence=evidence)
            
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)
        
    def form_on_ignore_list(self, form, ignore_list):
        """
        Check if the form is in the ignore list.

        Args:
            form (Tag): The form element.
            ignore_list (list): List of form IDs or names to ignore.

        Returns:
            bool: True if the form is in the ignore list, False otherwise.
        """
        form_id = form.get('id')
        form_name = form.get('name')
        for ignore in ignore_list:
            if ignore == form_id or ignore == form_name:
                logger.debug(f"Ignoring form with id/name = {ignore}")
                return True
        return False

    def get_csrf_ignore_list(self):
        """
        Get the list of forms to ignore for CSRF check.

        Returns:
            list: List of form IDs or names to ignore.
        """
        # Replace this method with the actual implementation to retrieve the ignore list from configuration
        return []

    def get_csrf_ignore_att_name(self):
        """
        Get the attribute name to ignore forms for CSRF check.

        Returns:
            str: The attribute name to ignore forms.
        """
        # Replace this method with the actual implementation to retrieve the ignore attribute name from configuration
        return None

    def get_csrf_ignore_att_value(self):
        """
        Get the attribute value to ignore forms for CSRF check.

        Returns:
            str: The attribute value to ignore forms.
        """
        # Replace this method with the actual implementation to retrieve the ignore attribute value from configuration
        return None

    def __str__(self) -> str:
        """
        Returns a string representation of the CsrfCountermeasuresScanRule object.

        Returns:
            str: A string representation of the CsrfCountermeasuresScanRule object.
        """
        return "CSRF Countermeasures Scan Rule"
    
    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 352 # CWE-352: Cross-Site Request Forgery (CSRF)

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 9 # WASC-9: Cross-Site Request Forgery
