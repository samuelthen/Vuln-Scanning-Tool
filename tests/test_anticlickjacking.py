import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.anticlickjacking_scan_rule import AntiClickjackingScanRule

class TestAntiClickjackingScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = AntiClickjackingScanRule()

    def test_no_html_content(self):
        self.set_response_content("", "application/json")
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_missing_x_frame_options(self):
        self.set_response_content("<html><body>Test</body></html>")
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(
            result,
            Risk.RISK_MEDIUM,
            Confidence.CONFIDENCE_MEDIUM,
            "X-Frame-Options header missing"
        )

    def test_invalid_x_frame_options(self):
        self.response.headers["X-Frame-Options"] = "INVALID"
        self.set_response_content("<html><body>Test</body></html>")
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(
            result,
            Risk.RISK_MEDIUM,
            Confidence.CONFIDENCE_MEDIUM
        )

    def test_multiple_x_frame_options(self):
        self.response.headers["X-Frame-Options"] = ["DENY", "SAMEORIGIN"]
        self.set_response_content("<html><body>Test</body></html>")
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(
            result,
            Risk.RISK_MEDIUM,
            Confidence.CONFIDENCE_MEDIUM
        )

    def test_valid_x_frame_options_deny(self):
        self.response.headers["X-Frame-Options"] = "DENY"
        self.set_response_content("<html><body>Test</body></html>")
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_valid_x_frame_options_sameorigin(self):
        self.response.headers["X-Frame-Options"] = "SAMEORIGIN"
        self.set_response_content("<html><body>Test</body></html>")
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_csp_with_frame_ancestors(self):
        self.response.headers["Content-Security-Policy"] = "frame-ancestors 'self'"
        self.set_response_content("<html><body>Test</body></html>")
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(
            result, 
            Risk.RISK_LOW,
            Confidence.CONFIDENCE_MEDIUM
        )

    def test_missing_x_frame_options_with_csp(self):
        self.response.headers["Content-Security-Policy"] = "frame-ancestors 'self'"
        self.set_response_content("<html><body>Test</body></html>")
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(
            result,
            Risk.RISK_LOW,
            Confidence.CONFIDENCE_MEDIUM
        )

    def test_invalid_x_frame_options_with_csp(self):
        self.response.headers["X-Frame-Options"] = "INVALID"
        self.response.headers["Content-Security-Policy"] = "frame-ancestors 'self'"
        self.set_response_content("<html><body>Test</body></html>")
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(
            result,
            Risk.RISK_LOW,
            Confidence.CONFIDENCE_MEDIUM
        )

    def test_exception_handling(self):
        self.response.headers = None  # This will cause an exception
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 1021)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 15)