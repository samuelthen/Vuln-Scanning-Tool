import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from bs4 import BeautifulSoup
from src.passive_scan.passive_scan_rules.content_security_policy_scan_rule import ContentSecurityPolicyScanRule
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.utils.common_alert_tag import CommonAlertTag
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest

class TestContentSecurityPolicyScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = ContentSecurityPolicyScanRule()

    def test_check_risk_with_csp_header(self):
        self.response.headers = {
            'Content-Security-Policy': "default-src 'self'; script-src 'unsafe-inline'"
        }
        self.response.text = "<html><body>Test</body></html>"

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_HIGH)

    def test_check_risk_with_xcsp_header(self):
        self.response.headers = {
            'X-Content-Security-Policy': "default-src 'self'"
        }
        self.response.text = "<html><body>Test</body></html>"

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_HIGH)

    def test_check_risk_with_xwebkit_csp_header(self):
        self.response.headers = {
            'X-WebKit-CSP': "default-src 'self'"
        }
        self.response.text = "<html><body>Test</body></html>"

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_HIGH)

    def test_check_risk_with_meta_csp(self):
        self.response.headers = {}
        self.response.text = """
        <html>
        <head>
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'unsafe-eval'">
        </head>
        <body>Test</body>
        </html>
        """

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_HIGH)

    def test_check_risk_with_malformed_csp(self):
        self.response.headers = {
            'Content-Security-Policy': "default-src 'self'; script-src 'unsafe-inline' ü"
        }
        self.response.text = "<html><body>Test</body></html>"

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_HIGH)

    def test_check_risk_with_wildcard_sources(self):
        self.response.headers = {
            'Content-Security-Policy': "default-src *; script-src *"
        }
        self.response.text = "<html><body>Test</body></html>"

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_HIGH)

    def test_check_risk_with_no_csp(self):
        self.response.headers = {}
        self.response.text = "<html><body>Test</body></html>"

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_with_exception(self):
        self.response.headers = Mock(side_effect=Exception("Test exception"))
        self.response.text = "<html><body>Test</body></html>"

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 693)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 15)

if __name__ == '__main__':
    unittest.main()