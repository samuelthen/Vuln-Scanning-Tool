import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)

class LinkTargetScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for _blank link targets without rel="noopener".
    """
    MSG_REF = "pscanrules.linktarget"
    RISK = Risk.RISK_MEDIUM
    CONFIDENCE = Confidence.CONFIDENCE_MEDIUM

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN,
        CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG
    ]

    TARGET_ATTRIBUTE = "target"
    REL_ATTRIBUTE = "rel"
    BLANK = "_blank"
    OPENER = "opener"
    NOOPENER = "noopener"

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for _blank link targets without rel="noopener".

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            if not self.is_html_response(response):
                return NoAlert(msg_ref=self.MSG_REF)

            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all(['a', 'area'])
            host = urlparse(request.url).netloc
            context_list = self.get_context_list(request.url)

            for link in links:
                href = link.get('href')
                if href and self.is_link_from_other_domain(host, href, context_list):
                    if self.check_element(link):
                        return Alert(risk_category=self.RISK,
                                     confidence=self.CONFIDENCE,
                                     description="Link with target='_blank' without rel='noopener'",
                                     msg_ref=self.MSG_REF,
                                     evidence=str(link),
                                     cwe_id=self.get_cwe_id(),
                                     wasc_id=self.get_wasc_id())
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def is_html_response(self, response: Response) -> bool:
        """
        Check if the response is HTML.

        Args:
            response (Response): The HTTP response object.

        Returns:
            bool: True if the response is HTML, False otherwise.
        """
        return 'text/html' in response.headers.get('Content-Type', '')

    def is_link_from_other_domain(self, host: str, link: str, context_list: list) -> bool:
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
        if link_host and link_host != host:
            return True
        
        for context in context_list:
            if context in link:
                return False
        return True

    def check_element(self, link) -> bool:
        """
        Check if the link has target="_blank" without rel="noopener".

        Args:
            link: The link element to check.

        Returns:
            bool: True if the link meets the conditions, False otherwise.
        """
        target = link.get(self.TARGET_ATTRIBUTE)
        if target and target.lower() == self.BLANK.lower():
            rel = link.get(self.REL_ATTRIBUTE, "")
            if isinstance(rel, list):
                rel = ' '.join(rel)  # Convert list to a space-separated string
            rel = rel.lower()
            if self.OPENER in rel and self.NOOPENER not in rel:
                return True
        return False

    def get_context_list(self, url: str) -> list:
        """
        Get the context list for the original URL.

        Args:
            url (str): The original URL.

        Returns:
            list: The context list.
        """
        # Implement a method to return the context list
        return []

    def __str__(self) -> str:
        """
        Returns a string representation of the LinkTargetScanRule object.

        Returns:
            str: A string representation of the LinkTargetScanRule object.
        """
        return "Link Target '_blank' without 'noopener'"

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 1022  # CWE-1022: Improper Restriction of Rendered UI Layers or Frames

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 14  # WASC-14: Server Misconfiguration
