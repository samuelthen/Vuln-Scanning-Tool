import logging
import re
import base64
from enum import Enum
from typing import List
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class ViewstateScanRule(BasePassiveScanRule):
    """
    Passive scan rule to check for ViewState issues in HTTP responses.
    """
    MSG_REF = "pscanrules.viewstate"
    RISK = Risk.RISK_MEDIUM
    CONFIDENCE = Confidence.CONFIDENCE_MEDIUM

    ALERT_TAGS = [
        CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN,
        CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
    ]

    hidden_field_pattern = re.compile("__.*")

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check for ViewState issues in the HTTP response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            source = response.text  # Assuming response text contains the HTML source
            hidden_fields = self.get_hidden_fields(source)

            if not hidden_fields:
                return NoAlert(msg_ref=self.MSG_REF)

            v = self.extract_viewstate(hidden_fields)
            
            if not v.check_validity():
                return NoAlert(msg_ref=self.MSG_REF)

            if not v.has_mac_test1() or not v.has_mac_test2():
                if not v.has_mac_test1() and not v.has_mac_test2():
                    return self.alert_no_mac_for_sure()
                else:
                    return self.alert_no_mac_unsure()

            if not v.is_latest_asp_net_version:
                return self.alert_old_asp_version()

            list_of_matches = ViewstateAnalyzer.get_search_results(v, self)
            for var in list_of_matches:
                if var.has_results():
                    return self.alert_viewstate_analyzer_result(var)

            if v.is_split:
                return self.alert_split_viewstate()

            return NoAlert(msg_ref=self.MSG_REF)
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return ScanError(description=str(e), msg_ref=self.MSG_REF)

    def alert_viewstate_analyzer_result(self, var):
        return Alert(
            risk_category=self.RISK,
            confidence=self.CONFIDENCE,
            description=var.pattern.pattern,
            msg_ref=self.MSG_REF,
            evidence=str(var.get_result_extract()),
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id()
        )

    def alert_old_asp_version(self):
        return Alert(
            risk_category=Risk.RISK_LOW,
            confidence=Confidence.CONFIDENCE_MEDIUM,
            description="This website uses ASP.NET version 1.0 or 1.1",
            msg_ref=self.MSG_REF + ".oldver",
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id()
        )

    def alert_no_mac_unsure(self):
        return Alert(
            risk_category=Risk.RISK_HIGH,
            confidence=Confidence.CONFIDENCE_LOW,
            description="This website uses ASP.NET's Viewstate but maybe without any MAC.",
            msg_ref=self.MSG_REF + ".nomac.unsure",
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id()
        )

    def alert_no_mac_for_sure(self):
        return Alert(
            risk_category=Risk.RISK_HIGH,
            confidence=Confidence.CONFIDENCE_MEDIUM,
            description="This website uses ASP.NET's Viewstate but without any MAC.",
            msg_ref=self.MSG_REF + ".nomac.sure",
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id()
        )

    def alert_split_viewstate(self):
        return Alert(
            risk_category=Risk.RISK_INFO,
            confidence=Confidence.CONFIDENCE_LOW,
            description="This website uses ASP.NET's Viewstate and its value is split into several chunks.",
            msg_ref=self.MSG_REF + ".split",
            cwe_id=self.get_cwe_id(),
            wasc_id=self.get_wasc_id()
        )

    def get_hidden_fields(self, source):
        # Mock function to extract hidden fields from the source
        hidden_fields = {}
        # Implement logic to extract hidden fields from the HTML source
        return hidden_fields

    def extract_viewstate(self, hidden_fields):
        if "__VIEWSTATEFIELDCOUNT" not in hidden_fields:
            return Viewstate(hidden_fields.get("__VIEWSTATE"))
        else:
            viewstate_value = hidden_fields.get("__VIEWSTATE")
            field_count = int(hidden_fields.get("__VIEWSTATEFIELDCOUNT"))
            for i in range(1, field_count):
                viewstate_value += hidden_fields.get(f"__VIEWSTATE{i}")
            return Viewstate(viewstate_value, was_split=True)

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 642  # CWE-642: External Control of Critical State Data

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 14  # WASC-14: Server Misconfiguration

    def __str__(self) -> str:
        """
        Returns a string representation of the ViewstateScanRule object.

        Returns:
            str: A string representation of the ViewstateScanRule object.
        """
        return "Viewstate Scan Rule"

class ViewstateVersion(Enum):
    UNKNOWN = 0
    ASPNET1 = 1
    ASPNET2 = 2

    def is_latest(self):
        return self == ViewstateVersion.ASPNET2

class Viewstate:
    def __init__(self, value, was_split=False):
        self.base64_value = value
        self.is_valid = True
        self.is_split = was_split
        self.decoded_value = self.base64_decode(self.base64_value)
        self.version = self.set_version()
        self.is_latest_asp_net_version = self.version == ViewstateVersion.ASPNET2

    def check_validity(self):
        return self.is_valid and (self.get_version() != ViewstateVersion.UNKNOWN)

    def check_split(self):
        return self.is_split

    def has_mac_test1(self):
        l = len(self.decoded_value)
        # Ensure the indices are correct for extracting the bytes before the MAC
        last_chars_before_mac = self.decoded_value[l - 22 : l - 20]

        if self.version == ViewstateVersion.ASPNET2:
            return last_chars_before_mac == b'\xdd\xdd'  # Use bytes comparison for ASP.NET 2.0

        if self.version == ViewstateVersion.ASPNET1:
            return last_chars_before_mac == b'\x3e\x3e'  # '>>' as bytes for ASP.NET 1.0

        return False  # Return False if the version is unknown


    def has_mac_test2(self):
        l = len(self.decoded_value)
        last_chars_before_mac = self.decoded_value[-2:]

        if self.version == ViewstateVersion.ASPNET2:
            return last_chars_before_mac != b"dd"

        if self.version == ViewstateVersion.ASPNET1:
            return last_chars_before_mac != b">>"

        return True

    def get_decoded_value(self):
        return self.decoded_value

    def get_version(self):
        return self.version

    def set_version(self):
        if self.base64_value.startswith("/w"):
            return ViewstateVersion.ASPNET2

        if self.base64_value.startswith("dD"):
            return ViewstateVersion.ASPNET1
        
        return ViewstateVersion.UNKNOWN

    def base64_decode(self, value):
        try:
            # Add padding if necessary
            missing_padding = len(value) % 4
            if missing_padding:
                value += '=' * (4 - missing_padding)
            return base64.b64decode(value)
        except Exception as e:
            self.is_valid = False
            logger.error(f"Invalid base64: {str(e)}")
            return b""

            
class ViewstateAnalyzer:
    @staticmethod
    def get_search_results(v, s):
        results = []
        for pattern in [ViewstateAnalyzerPattern.EMAIL, ViewstateAnalyzerPattern.IPADDRESS]:
            matches = pattern.findall(v.decoded_value)
            result = ViewstateAnalyzerResult(pattern)
            for match in matches:
                result.add_results(match)
            results.append(result)
        return results

class ViewstateAnalyzerResult:
    def __init__(self, pattern):
        self.pattern = pattern
        self.result_extract = set()

    def add_results(self, s):
        self.result_extract.add(s)

    def has_results(self):
        return bool(self.result_extract)

    def get_result_extract(self):
        return self.result_extract

    def get_alert_ref(self):
        return self.pattern.pattern

class ViewstateAnalyzerPattern:
    EMAIL = re.compile("[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,4}", re.IGNORECASE)
    IPADDRESS = re.compile("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")
