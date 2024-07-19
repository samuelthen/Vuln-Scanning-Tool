import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.x_backend_server_information_leak_scan_rule import XBackendServerInformationLeakScanRule

class TestXBackendServerInformationLeakScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = XBackendServerInformationLeakScanRule()

    def test_check_risk_with_x_backend_server_header(self):
        self.response.headers = {
            'Content-Type': 'text/html',
            'X-Backend-Server': 'backend1.example.com'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)
        self.assertEqual(result.evidence, 'backend1.example.com')

    def test_check_risk_without_x_backend_server_header(self):
        self.response.headers = {
            'Content-Type': 'text/html'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_with_exception(self):
        self.response.headers = Mock()
        self.response.headers.get.side_effect = Exception("Test exception")
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 200)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 13)

if __name__ == '__main__':
    unittest.main()
