import logging
import re
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError

logger = logging.getLogger(__name__)

class DirectoryBrowsingScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for directory browsing/listing enabled.
    """

    # Predefined patterns for detecting directory browsing in response body
    server_patterns = {
        re.compile(r"<title>Index of /[^<]+?</title>", re.MULTILINE | re.DOTALL): "Apache 2",
        re.compile(r"<pre><A\s+HREF\s*=\s*\"/[^>]*\">\[To Parent Directory\]</A><br><br>", re.MULTILINE | re.DOTALL): "Microsoft IIS"
    }

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for directory browsing/listing indicators in the HTTP response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            # Check if the response is HTML
            if "Content-Type" in response.headers and "text/html" in response.headers["Content-Type"]:
                response_body = response.text

                # Iterate over the predefined patterns
                for pattern, server in self.server_patterns.items():
                    if pattern.search(response_body):
                        evidence = pattern.search(response_body).group()
                        return Alert(risk_category="Medium",
                                     description=f"Directory browsing enabled on {server} server.",
                                     msg_ref="pscanrules.directorybrowsing.detected",
                                     evidence=evidence,
                                     cwe_id=self.get_cwe_id(),
                                     wasc_id=self.get_wasc_id())
            return NoAlert()
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logging.error(f"Error during scan: {e}")
            return ScanError(description=str(e))

    def __str__(self) -> str:
        """
        Returns a string representation of the DirectoryBrowsingScanRule object.

        Returns:
            str: A string representation of the DirectoryBrowsingScanRule object.
        """
        return "Directory Browsing Detection"

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 548 # CWE-548: Information Exposure Through Directory Listing

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 16 # WASC-16: Directory Indexing
