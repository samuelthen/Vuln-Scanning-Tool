import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.x_content_type_options_scan_rule import XContentTypeOptionsScanRule

class TestXContentTypeOptionsScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = XContentTypeOptionsScanRule()

    def test_check_risk_no_x_content_type_options_header(self):
        self.response.headers = {
            'Content-Type': 'text/html'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)
        self.assertEqual(result.description, "X-Content-Type-Options header missing")

    def test_check_risk_incorrect_x_content_type_options_header(self):
        self.response.headers = {
            'Content-Type': 'text/html',
            'X-Content-Type-Options': 'invalid-value'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)
        self.assertEqual(result.description, "X-Content-Type-Options header set incorrectly")
        self.assertEqual(result.evidence, 'invalid-value')

    def test_check_risk_correct_x_content_type_options_header(self):
        self.response.headers = {
            'Content-Type': 'text/html',
            'X-Content-Type-Options': 'nosniff'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_no_body(self):
        self.response.headers = {
            'Content-Type': 'text/html',
            'X-Content-Type-Options': 'nosniff'
        }
        self.response.content = b''

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_exception(self):
        self.response.headers = {'Content-Type': 'text/html'}
        self.response.content = b'Some content'
        
        # Simulate an exception
        self.response.headers = Mock(side_effect=Exception("Test exception"))

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 693)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 15)

if __name__ == '__main__':
    unittest.main()
