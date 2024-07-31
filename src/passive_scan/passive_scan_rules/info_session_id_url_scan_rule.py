import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag
from urllib.parse import urlparse
import re

logger = logging.getLogger(__name__)

class InfoSessionIdUrlScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for session IDs in URLs.
    """
    MSG_REF = "pscanrules.infosessionidurl"
    RISK = Risk.RISK_MEDIUM
    CONFIDENCE = Confidence.CONFIDENCE_HIGH

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
        CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED,
        CommonAlertTag.WSTG_V42_SESS_04_SESS_EXPOSED
    ]

    SESSION_IDS = ["asp.net_sessionid",
                    "aspsessionid",
                    "siteserver",
                    "cfid",
                    "cftoken",
                    "jsessionid",
                    "phpsessid",
                    "sessid",
                    "sid",
                    "viewstate",
                    "zenid"]

    SESSION_TOKEN_MIN_LENGTH = 8

    @classmethod
    def get_path_session_id_pattern(cls):
        return re.compile(
            r"|".join([f"{keyword}=[\\dA-Z]{{{cls.SESSION_TOKEN_MIN_LENGTH},}}" for keyword in cls.SESSION_IDS]),
            re.IGNORECASE
        )

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for session IDs in URLs.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            url_params = self.get_url_params(request)

            session_ids = self.get_session_ids()

            for param_name, param_value in url_params.items():
                if param_name.lower() in session_ids and len(param_value) > self.SESSION_TOKEN_MIN_LENGTH:
                    return Alert(
                        risk_category=self.RISK,
                        confidence=self.CONFIDENCE,
                        description="Session ID found in URL parameter",
                        msg_ref=self.MSG_REF,
                        evidence=f"{param_name}={param_value}",
                        cwe_id=self.get_cwe_id(),
                        wasc_id=self.get_wasc_id()
                    )

            match = self.get_path_session_id_pattern().search(request.url)

            if match:
                return Alert(
                    risk_category=self.RISK,
                    confidence=self.CONFIDENCE,
                    description="Session ID found in URL path",
                    msg_ref=self.MSG_REF,
                    evidence=match.group(0),
                    cwe_id=self.get_cwe_id(),
                    wasc_id=self.get_wasc_id()
                )
            
            # Implement when return a list of alert
            # self.check_session_id_exposure_to_3rd_party(response) 

            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def get_session_ids(self):
        """
        Get the list of session IDs to check for.

        Returns:
            list: A list of session ID names.
        """
        # Implement a method to retrieve the list of session IDs from configuration or constants
        return self.SESSION_IDS

    def get_url_params(self, request: Request) -> dict:
        """
        Extract URL parameters from the request.

        Args:
            request (Request): The HTTP request object.

        Returns:
            dict: A dictionary of URL parameters and their values.
        """
        parsed_url = urlparse(request.url)
        return dict(re.findall(r'([^&=]+)=([^&]*)', parsed_url.query))

    def __str__(self) -> str:
        """
        Returns a string representation of the InfoSessionIdUrlScanRule object.

        Returns:
            str: A string representation of the InfoSessionIdUrlScanRule object.
        """
        return "Info Session ID URL Scan Rule"

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 200  # CWE-200: Information Exposure

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 13  # WASC-13: Info leakage

    # def check_session_id_exposure_to_3rd_party(self, response: Response) -> Alert:
    #     """
    #     Check if the session ID might be exposed to 3rd-parties via external links in the response.

    #     Args:
    #         response (Response): The HTTP response object.

    #     Returns:
    #         Alert: An Alert object indicating the result of the exposure check.
    #     """
    #     body = response.text
    #     host = urlparse(response.url).hostname

    #     ext_link_patterns = [
    #         re.compile(r'src\s*=\s*[\'"]?(https?://[\w\.\-_]+)', re.IGNORECASE),
    #         re.compile(r'href\s*=\s*[\'"]?(https?://[\w\.\-_]+)', re.IGNORECASE),
    #         re.compile(r'[=\(]\s*[\'"](https?://[\w\.\-_]+)', re.IGNORECASE)
    #     ]

    #     for pattern in ext_link_patterns:
    #         match = pattern.search(body)
    #         if match:
    #             link_hostname = urlparse(match.group(1)).hostname
    #             if link_hostname and host != link_hostname:
    #                 return Alert(
    #                     risk_category=self.RISK,
    #                     confidence=Confidence.CONFIDENCE_MEDIUM,
    #                     description="Session ID might be exposed to 3rd-party",
    #                     msg_ref=self.MSG_REF,
    #                     evidence=match.group(1),
    #                     cwe_id=self.get_cwe_id(),
    #                     wasc_id=self.get_wasc_id()
    #                 )

    #     return NoAlert(msg_ref=self.MSG_REF)
