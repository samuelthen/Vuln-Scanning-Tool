import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from src.passive_scan.passive_scan_rules.server_header_info_leak_scan_rule import ServerHeaderInfoLeakScanRule
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest

class TestServerHeaderInfoLeakScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = ServerHeaderInfoLeakScanRule()

    def test_check_risk_server_header_with_version_info(self):
        self.response.headers = {
            'Server': 'Apache/2.4.41 (Ubuntu)'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_HIGH)
        self.assertEqual(result.evidence, 'Apache/2.4.41 (Ubuntu)')

    def test_check_risk_server_header_without_version_info(self):
        self.response.headers = {
            'Server': 'Apache'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_HIGH)
        self.assertEqual(result.evidence, 'Apache')

    def test_check_risk_no_server_header(self):
        self.response.headers = {
            'Content-Type': 'text/html'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_multiple_server_headers(self):
        self.response.headers = {
            'Server': 'nginx/1.18.0, Apache/2.4.41 (Ubuntu)'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_HIGH)
        self.assertEqual(result.evidence, 'nginx/1.18.0')

    def test_check_risk_exception(self):
        self.request.url = 'https://example.com'
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
