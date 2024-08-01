import re
import logging
from requests.models import Request, Response
from bs4 import BeautifulSoup
import tldextract
from urllib.parse import urlparse
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class StrictTransportSecurityScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for Strict-Transport-Security headers and their correct configuration.
    """
    MSG_REF = "pscanrules.stricttransportsecurity"
    RISK = Risk.RISK_LOW
    CONFIDENCE = Confidence.CONFIDENCE_HIGH

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
        CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG
    ]

    STS_HEADER = "Strict-Transport-Security"
    BAD_MAX_AGE_PATT = re.compile(r"\bmax-age\s*=\s*\'*\"*\s*0\s*\"*\'*\s*", re.IGNORECASE)
    MAX_AGE_PATT = re.compile(r"\bmax-age\s*=\s*\'*\"*\s*\d+\s*\"*\'*\s*", re.IGNORECASE)
    MALFORMED_MAX_AGE = re.compile(r"['+|\"+]\s*max", re.IGNORECASE)
    WELL_FORMED_PATT = re.compile(r"[ -~]*", re.IGNORECASE)  # Corrected pattern

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for issues with the Strict-Transport-Security header.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            # Only check secure (HTTPS) responses
            alert = []
            if request.url.startswith("https://"):
                # Check for META tag HSTS first
                

                # Check for STS header
                sts_headers = response.headers.get(self.STS_HEADER)

                meta_hsts = self.get_meta_hsts_evidence(response)
                if meta_hsts:
                    alert.append(Alert(risk_category=self.RISK,
                                confidence=self.CONFIDENCE, 
                                description="Strict-Transport-Security set via META tag",
                                msg_ref="pscanrules.stricttransportsecurity.compliance.meta",
                                cwe_id=self.get_cwe_id(), 
                                wasc_id=self.get_wasc_id()))
                
                if not sts_headers:
                    if self.is_redirect(response):
                        location_header = response.headers.get('Location')
                        if location_header:
                            try:
                                redir_uri = urlparse(location_header)
                                if self.is_link_from_other_domain(request.url, location_header) and redir_uri.scheme == 'https':
                                    return NoAlert(msg_ref=self.MSG_REF)
                            except Exception as e:
                                print(f"Error parsing URLs: {e}")
                    alert.append(Alert(risk_category=self.RISK,
                                confidence=self.CONFIDENCE, 
                                description="Strict-Transport-Security header missing",
                                msg_ref="pscanrules.stricttransportsecurity",
                                cwe_id=self.get_cwe_id(), 
                                wasc_id=self.get_wasc_id()))
                else:
                    if isinstance(sts_headers, list):
                        if len(sts_headers) > 1:
                            alert.append(Alert(risk_category=self.RISK,
                                        confidence=self.CONFIDENCE, 
                                        description="Multiple Strict-Transport-Security headers found",
                                        msg_ref="pscanrules.stricttransportsecurity.compliance.multiple.header",
                                        cwe_id=self.get_cwe_id(), 
                                        wasc_id=self.get_wasc_id()))
                        sts_headers = sts_headers[0]  # Use the first header if there's only one

                    sts_option_string = sts_headers.lower()
                    if not self.WELL_FORMED_PATT.match(sts_option_string):
                        alert.append(Alert(risk_category=self.RISK,
                                    confidence=self.CONFIDENCE, 
                                    description="Malformed Strict-Transport-Security header content",
                                    msg_ref="pscanrules.stricttransportsecurity.compliance.malformed.content",
                                    cwe_id=self.get_cwe_id(), 
                                    wasc_id=self.get_wasc_id()))
                    if self.BAD_MAX_AGE_PATT.search(sts_option_string):
                        alert.append(Alert(risk_category=self.RISK,
                                    confidence=self.CONFIDENCE, 
                                    description="Strict-Transport-Security header with max-age=0",
                                    msg_ref="pscanrules.stricttransportsecurity.max.age",
                                    cwe_id=self.get_cwe_id(), 
                                    wasc_id=self.get_wasc_id()))
                    if not self.MAX_AGE_PATT.search(sts_option_string):
                        alert.append(Alert(risk_category=self.RISK,
                                    confidence=self.CONFIDENCE, 
                                    description="Strict-Transport-Security header missing max-age",
                                    msg_ref="pscanrules.stricttransportsecurity.compliance.max.age.missing",
                                    cwe_id=self.get_cwe_id(), 
                                    wasc_id=self.get_wasc_id()))                    
                    if self.MALFORMED_MAX_AGE.search(sts_option_string):
                        alert.append(Alert(risk_category=self.RISK,
                                    confidence=self.CONFIDENCE, 
                                    description="Malformed max-age in Strict-Transport-Security header",
                                    msg_ref="pscanrules.stricttransportsecurity.compliance.max.age.malformed",
                                    cwe_id=self.get_cwe_id(), 
                                    wasc_id=self.get_wasc_id()))
            else:
                # Check for STS headers in non-HTTPS responses at low threshold
                if response.headers.get(self.STS_HEADER):
                    alert.append(Alert(risk_category=Risk.RISK_INFO,
                                confidence=self.CONFIDENCE, 
                                description="Strict-Transport-Security header present on non-HTTPS response",
                                msg_ref="pscanrules.stricttransportsecurity.plain.resp",
                                cwe_id=self.get_cwe_id(), 
                                wasc_id=self.get_wasc_id()))

            if alert:
                return alert[0]
            else:
                return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            # Handle any exceptions that occur during the scan
            print(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def get_meta_hsts_evidence(self, response: Response) -> str:
        """
        Check the HTML content for META tag setting HSTS.

        Args:
            response (Response): The HTTP response object.

        Returns:
            str: The META tag content if found, otherwise None.
        """

        if "text/html" in response.headers.get("Content-Type", ""):
            soup = BeautifulSoup(response.text, 'html.parser')
            meta_tags = soup.find_all('meta', attrs={'http-equiv': self.STS_HEADER})
            if meta_tags:
                return str(meta_tags[0])
        return None

    def is_redirect(self, response: Response) -> bool:
        """
        Check if the response is a redirect.

        Args:
            response (Response): The HTTP response object.

        Returns:
            bool: True if the response is a redirect, otherwise False.
        """
        return response.status_code in range(300, 400) and 'Location' in response.headers

    def is_link_from_other_domain(self, host: str, link: str) -> bool:
        """
        Check if the link is from another domain.

        Args:
            host (str): The host of the original request.
            link (str): The link to check.
            context_list (list): The context list for the original URL.

        Returns:
            bool: True if the link is from another domain, False otherwise.
        """
        parsed_link = urlparse(link)

        if not parsed_link.netloc:
            return False

        link_host = parsed_link.netloc

        # Extract the domain and suffix from the host and link
        host_extract = tldextract.extract(host)
        link_host_extract = tldextract.extract(link_host)

        host_domain = f"{host_extract.domain}.{host_extract.suffix}"
        link_domain = f"{link_host_extract.domain}.{link_host_extract.suffix}"

        # Compare the domains instead of the full hostnames
        if link_domain != host_domain:
            return True

        return True

    def __str__(self) -> str:
        """
        Returns a string representation of the StrictTransportSecurityScanRule object.

        Returns:
            str: A string representation of the StrictTransportSecurityScanRule object.
        """
        return "Strict-Transport-Security (HSTS) Header"

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 319 # CWE-319: Cleartext Transmission of Sensitive Information

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 15 # WASC-15: Application Misconfiguration
