import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from src.passive_scan.passive_scan_rules.x_asp_net_version_scan_rule import XAspNetVersionScanRule
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest

class TestXAspNetVersionScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = XAspNetVersionScanRule()

    def test_check_risk_with_x_aspnet_version_header(self):
        self.response.headers = {
            'Content-Type': 'text/html',
            'X-AspNet-Version': '4.0.30319'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_HIGH)
        self.assertEqual(result.evidence, '4.0.30319')

    def test_check_risk_with_x_aspnetmvc_version_header(self):
        self.response.headers = {
            'Content-Type': 'text/html',
            'X-AspNetMvc-Version': '5.2'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_HIGH)
        self.assertEqual(result.evidence, '5.2')

    def test_check_risk_without_aspnet_headers(self):
        self.response.headers = {
            'Content-Type': 'text/html'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_empty_response(self):
        self.response.headers = {
            'Content-Type': 'text/html'
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
        self.assertEqual(self.scan_rule.get_cwe_id(), 933)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 14)

if __name__ == '__main__':
    unittest.main()
