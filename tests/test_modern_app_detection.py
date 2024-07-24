import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from bs4 import BeautifulSoup
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.modern_app_detection_scan_rule import ModernAppDetectionScanRule

class TestModernAppDetectionScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = ModernAppDetectionScanRule()

    def test_check_risk_non_html_response(self):
        self.response.headers['Content-Type'] = 'application/json'
        self.response.text = '{"key": "value"}'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_no_links_with_scripts(self):
        self.set_response_content('<html><body><script src="app.js"></script></body></html>')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)
        self.assertIn("No links found but scripts are present", result.other_info)

    def test_check_risk_links_with_empty_href(self):
        self.set_response_content('<html><body><a href="">Empty link</a></body></html>')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)
        self.assertIn("Links with empty href or # found", result.other_info)

    def test_check_risk_links_with_hash_href(self):
        self.set_response_content('<html><body><a href="#">Hash link</a></body></html>')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)
        self.assertIn("Links with empty href or # found", result.other_info)

    def test_check_risk_links_with_target_self(self):
        self.set_response_content('<html><body><a href="page.html" target="_self">Self-target link</a></body></html>')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)
        self.assertIn("Links with target='_self' found", result.other_info)

    def test_check_risk_with_noscript(self):
        self.set_response_content('<html><body><noscript>JavaScript is disabled</noscript></body></html>')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)
        self.assertIn("Noscript tag found", result.other_info)

    def test_check_risk_no_modern_app_indicators(self):
        self.set_response_content('<html><body><a href="page.html">Normal link</a></body></html>')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_exception(self):
        self.response.text = Mock(side_effect=Exception("Test exception"))

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 829)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 20)

if __name__ == '__main__':
    unittest.main()