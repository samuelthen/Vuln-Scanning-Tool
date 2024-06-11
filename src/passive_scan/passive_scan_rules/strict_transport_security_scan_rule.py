import re
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError

class StrictTransportSecurityScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for Strict-Transport-Security headers and their correct configuration.
    """

    STS_HEADER = "Strict-Transport-Security"
    BAD_MAX_AGE_PATT = re.compile(r"\bmax-age\s*=\s*\'*\"*\s*0\s*\"*\'*\s*", re.IGNORECASE)
    MAX_AGE_PATT = re.compile(r"\bmax-age\s*=\s*\'*\"*\s*\d+\s*\"*\'*\s*", re.IGNORECASE)
    MALFORMED_MAX_AGE = re.compile(r"['+|\"+]\s*max", re.IGNORECASE)
    WELL_FORMED_PATT = re.compile(r"[ -~]*", re.IGNORECASE)  # Corrected pattern

    def check_risk(self, request: Request, response: Response) -> str:
        """
        Check for issues with the Strict-Transport-Security header.

        Returns:
        - Alert
        """
        try:
            # Only check secure (HTTPS) responses
            if request.url.startswith("https://"):
                sts_headers = response.headers.get(self.STS_HEADER, None)
                meta_hsts = self.get_meta_hsts_evidence(response)

                if not sts_headers:
                    if not self.is_redirect(response):
                        return Alert(risk_category="Low", description="Strict-Transport-Security header missing",
                                     cwe_id=self.get_cwe_id(), wasc_id=self.get_wasc_id())
                    else:
                        return Alert(risk_category="Low", description="redirect to HTTPS with missing STS header",
                                     cwe_id=self.get_cwe_id(), wasc_id=self.get_wasc_id())
                else:
                    sts_option_string = sts_headers.lower()
                    if not self.WELL_FORMED_PATT.match(sts_option_string):
                        return Alert(risk_category="Low", description="malformed Strict-Transport-Security header content",
                                     cwe_id=self.get_cwe_id(), wasc_id=self.get_wasc_id())
                    if self.BAD_MAX_AGE_PATT.search(sts_option_string):
                        return Alert(risk_category="Low", description="Strict-Transport-Security header with max-age=0",
                                     cwe_id=self.get_cwe_id(), wasc_id=self.get_wasc_id())
                    if not self.MAX_AGE_PATT.search(sts_option_string):
                        return Alert(risk_category="Low", description="Strict-Transport-Security header missing max-age",
                                     cwe_id=self.get_cwe_id(), wasc_id=self.get_wasc_id())                    
                    if self.MALFORMED_MAX_AGE.search(sts_option_string):
                        return Alert(risk_category="Low", description="malformed max-age in Strict-Transport-Security header",
                                     cwe_id=self.get_cwe_id(), wasc_id=self.get_wasc_id())   

                if meta_hsts:
                    return Alert(risk_category="Low", description="Strict-Transport-Security set via META tag",
                                 cwe_id=self.get_cwe_id(), wasc_id=self.get_wasc_id())   

            else:
                # Check for STS headers in non-HTTPS responses at low threshold
                if response.headers.get(self.STS_HEADER, None):
                    return Alert(risk_category="Informational", description="Strict-Transport-Security header present on non-HTTPS response",
                                 cwe_id=self.get_cwe_id(), wasc_id=self.get_wasc_id())   

            return NoAlert()
        except Exception as e:
            # Handle any exceptions that occur during the scan
            print(f"Error during scan: {e}")
            return ScanError(description=e)

    def get_meta_hsts_evidence(self, response: Response) -> str:
        """
        Checks the HTML content for META tag setting HSTS.

        Returns:
        - str: The META tag content if found, otherwise None.
        """
        if "text/html" in response.headers.get("Content-Type", ""):
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            meta_tags = soup.find_all('meta', attrs={'http-equiv': self.STS_HEADER})
            if meta_tags:
                return str(meta_tags[0])
        return None

    def is_redirect(self, response: Response) -> bool:
        """
        Check if the response is a redirect.

        Returns:
        - bool: True if the response is a redirect, otherwise False.
        """
        return response.status_code in range(300, 400) and 'Location' in response.headers

    def __str__(self) -> str:
        return "Strict-Transport-Security (HSTS) Header"

    def get_cwe_id(self):
        return 319 # CWE-319: Cleartext Transmission of Sensitive Information

    def get_wasc_id(self):
        return 15 # WASC-15: Application Misconfiguration