import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class CrossDomainMisconfigurationScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for cross-domain misconfigurations in HTTP responses.
    """

    MSG_REF = "pscanrules.crossdomain"
    RISK = Risk.RISK_MEDIUM
    CONFIDENCE = Confidence.CONFIDENCE_MEDIUM

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
        CommonAlertTag.OWASP_2017_A05_BROKEN_AC
    ]
    
    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for cross-domain misconfigurations in the HTTP response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            logger.debug(f"Checking message {request.url} for Cross-Domain misconfigurations")

            cors_allow_origin_value = response.headers.get("Access-Control-Allow-Origin")

            if cors_allow_origin_value is not None and cors_allow_origin_value == "*":
                logger.debug(f"Raising a Medium risk Cross Domain alert on Access-Control-Allow-Origin: {cors_allow_origin_value}")
                
                return Alert(
                    risk_category=self.RISK,
                    confidence=self.CONFIDENCE,
                    description=self.get_description(),
                    msg_ref=self.MSG_REF,
                    cwe_id=self.get_cwe_id(),
                    wasc_id=self.get_wasc_id(),
                    evidence=self.extract_evidence(response.headers, "Access-Control-Allow-Origin", cors_allow_origin_value)
                )
            
            return NoAlert(msg_ref=self.MSG_REF)
        
        except Exception as e:
            logger.error(f"An error occurred trying to passively scan a message for Cross Domain Misconfigurations: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)
        
    def extract_evidence(self, headers, header_name, header_contents) -> str:
        """
        Extract evidence from the headers.

        Args:
            headers (dict): The HTTP response headers.
            header_name (str): The name of the header to find.
            header_contents (str): The contents of the header to find.

        Returns:
            str: The extracted evidence.
        """
        evidence = f"{header_name}: {header_contents}"
        return evidence if evidence in str(headers) else ""

    def __str__(self) -> str:
        """
        Returns a string representation of the CrossDomainMisconfigurationScanRule object.

        Returns:
            str: A string representation of the CrossDomainMisconfigurationScanRule object.
        """
        return "Cross-Domain Misconfiguration Scan Rule"
    
    def get_cwe_id(self) -> int:
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 264  # CWE-264: Permissions, Privileges, and Access Controls

    def get_wasc_id(self) -> int:
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 14  # WASC-14: Server Misconfiguration

    def get_description(self) -> str:
        """
        Get the description of the alert.

        Returns:
            str: The description of the alert.
        """
        return "Cross-Domain Misconfiguration detected. The 'Access-Control-Allow-Origin' header is set to '*', which allows any domain to access the resources."

