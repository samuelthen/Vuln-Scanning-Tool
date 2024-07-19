import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.x_debug_token_scan_rule import XDebugTokenScanRule

class TestXDebugTokenScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = XDebugTokenScanRule()

    def test_no_x_debug_headers(self):
        self.response.headers = {
            'Content-Type': 'text/html',
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_x_debug_token_header_present(self):
        self.response.headers = {
            'Content-Type': 'text/html',
            'X-Debug-Token': 'some-token'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_HIGH)
        self.assertEqual(result.evidence, 'some-token')

    def test_x_debug_token_link_header_present(self):
        self.response.headers = {
            'Content-Type': 'text/html',
            'X-Debug-Token-Link': 'some-link'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_HIGH)
        self.assertEqual(result.evidence, 'some-link')

    def test_both_x_debug_headers_present(self):
        self.response.headers = {
            'Content-Type': 'text/html',
            'X-Debug-Token': 'some-token',
            'X-Debug-Token-Link': 'some-link'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        # Depending on the implementation, the scan rule might alert on the first header found.
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_HIGH)
        self.assertIn(result.evidence, ['some-token', 'some-link'])

    def test_check_risk_exception(self):
        self.response.headers = {'Content-Type': 'text/html'}
        self.response.content = b'Some content'
        
        # Simulate an exception
        self.response.headers = Mock(side_effect=Exception("Test exception"))

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)
        
    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 200)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 13)

if __name__ == '__main__':
    unittest.main()
