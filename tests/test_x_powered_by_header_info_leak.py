import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.x_powered_by_header_info_leak_scan_rule import XPoweredByHeaderInfoLeakScanRule

class TestXPoweredByHeaderInfoLeakScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = XPoweredByHeaderInfoLeakScanRule()

    def test_check_risk_with_x_powered_by_header(self):
        self.response.headers = {
            'Content-Type': 'text/html',
            'X-Powered-By': 'PHP/7.4.3'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)
        self.assertEqual(result.evidence, 'X-Powered-By: PHP/7.4.3')

    def test_check_risk_with_multiple_x_powered_by_headers(self):
        self.response.headers = {
            'Content-Type': 'text/html',
            'X-Powered-By': 'PHP/7.4.3, ASP.NET'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)
        self.assertIn('PHP/7.4.3', result.evidence)
        self.assertIn('ASP.NET', result.evidence)

    def test_check_risk_without_x_powered_by_header(self):
        self.response.headers = {
            'Content-Type': 'text/html'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_empty_response_with_x_powered_by_header(self):
        self.response.headers = {
            'Content-Type': 'text/html',
            'X-Powered-By': 'PHP/7.4.3'
        }
        self.response.content = b''

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)
        self.assertEqual(result.evidence, 'X-Powered-By: PHP/7.4.3')

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
