import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError

logger = logging.getLogger(__name__)

class CsrfCountermeasuresScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for CSRF countermeasures in HTML forms.
    """
    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for CSRF countermeasures in HTML forms.

        Returns:
        - Alert if a form without CSRF countermeasures is found.
        - NoAlert if all forms have CSRF countermeasures.
        """
        try:
            # Check if the response is HTML
            if "Content-Type" in response.headers and "text/html" in response.headers["Content-Type"]:
                # Parse the HTML response
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
                
                forms = soup.find_all('form')
                if not forms:
                    return NoAlert()

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
                        return Alert(risk_category="Medium", 
                                     description="Form without CSRF countermeasures", 
                                     msg_ref="pscanrules.noanticsrftokens", 
                                     cwe_id=self.get_cwe_id(), 
                                     wasc_id=self.get_wasc_id(), 
                                     evidence=evidence)
            
            return NoAlert()
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e))
        
    def form_on_ignore_list(self, form, ignore_list):
        form_id = form.get('id')
        form_name = form.get('name')
        for ignore in ignore_list:
            if ignore == form_id or ignore == form_name:
                logger.debug(f"Ignoring form with id/name = {ignore}")
                return True
        return False

    def get_csrf_ignore_list(self):
        # Replace this method with the actual implementation to retrieve the ignore list from configuration
        return []

    def get_csrf_ignore_att_name(self):
        # Replace this method with the actual implementation to retrieve the ignore attribute name from configuration
        return None

    def get_csrf_ignore_att_value(self):
        # Replace this method with the actual implementation to retrieve the ignore attribute value from configuration
        return None

    def __str__(self) -> str:
        return "CSRF Countermeasures Scan Rule"
    
    def get_cwe_id(self):
        return 352 # CWE-352: Cross-Site Request Forgery (CSRF)

    def get_wasc_id(self):
        return 9 # WASC-9: Cross-Site Request Forgery
