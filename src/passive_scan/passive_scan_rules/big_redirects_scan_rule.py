import logging
import re
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class BigRedirectsScanRule(BasePassiveScanRule):
    """
    Passive scan rule to detect big redirects and multiple href attributes in redirects.
    """
    MSG_REF = "pscanrules.bigredirects"
    RISK = Risk.RISK_LOW
    CONFIDENCE = Confidence.CONFIDENCE_MEDIUM

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN,
        CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED,
        CommonAlertTag.WSTG_V42_INFO_05_CONTENT_LEAK
    ]

    HREF_PATTERN = re.compile(r'href', re.IGNORECASE)
    PLUGIN_ID = 10044
    
    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for big redirects and multiple href attributes in the HTTP response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            # Check if the response is a redirect
            if 300 <= response.status_code < 400 and response.status_code != 304:
                location_header = response.headers.get('Location')
                if location_header:
                    response_location_header_uri_length = len(location_header)
                else:
                    logger.debug("Redirect status code with no Location header.\nRequested URL: %s", request.url)
                    return NoAlert(msg_ref=self.MSG_REF)
                
                predicted_response_size = self.get_predicted_response_size(response_location_header_uri_length)
                response_body_length = len(response.text)
                
                if response_body_length > predicted_response_size:
                    return self.create_big_alert(
                        response_location_header_uri_length,
                        location_header,
                        predicted_response_size,
                        response_body_length
                    )
                else:
                    href_count = len(self.HREF_PATTERN.findall(response.text))
                    if href_count > 1:
                        return self.create_multi_alert(href_count)
            
            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            # Handle any exceptions that occur during the scan
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def get_predicted_response_size(self, redirect_uri_length: int) -> int:
        """
        Calculate the predicted size of the response body based on the URI length.

        Args:
            redirect_uri_length (int): The length of the URI in the Location header.

        Returns:
            int: The predicted response size.
        """
        predicted_response_size = redirect_uri_length + 300
        logger.debug("Original Response Location Header URI Length: %d", redirect_uri_length)
        logger.debug("Predicted Response Size: %d", predicted_response_size)
        return predicted_response_size

    def create_big_alert(self, url_length: int, url: str, predicted_max_length: int, actual_max_length: int) -> Alert:
        """
        Create an alert for a big redirect.

        Args:
            url_length (int): The length of the URL in the Location header.
            url (str): The URL in the Location header.
            predicted_max_length (int): The predicted maximum length of the response.
            actual_max_length (int): The actual length of the response.

        Returns:
            Alert: The created alert object.
        """
        return Alert(
            risk_category=self.RISK,
            confidence=self.CONFIDENCE,
            description="Big redirect detected",
            msg_ref=self.MSG_REF,
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id(),
            other_info=f"URL Length: {url_length}, URL: {url}, Predicted Max Length: {predicted_max_length}, Actual Max Length: {actual_max_length}"
        )
    
    def create_multi_alert(self, href_count: int) -> Alert:
        """
        Create an alert for multiple href attributes.

        Args:
            href_count (int): The number of href attributes found in the response body.

        Returns:
            Alert: The created alert object.
        """
        return Alert(
            risk_category=self.RISK,
            confidence=self.CONFIDENCE,
            description="Multiple href attributes detected in redirect",
            msg_ref=f"{self.MSG_REF}.multi",
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id(),
            other_info=f"Number of href attributes: {href_count}"
        )
    
    def __str__(self) -> str:
        """
        Returns a string representation of the BigRedirectsScanRule object.

        Returns:
            str: A string representation of the BigRedirectsScanRule object.
        """
        return "Big Redirects"
    
    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 201 # CWE-201: Information Exposure Through Sent Data

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 13 # WASC-13: Information Leakage
