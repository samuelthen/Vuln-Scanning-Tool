import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.cross_domain_misconfiguration_scan_rule import CrossDomainMisconfigurationScanRule

class TestCrossDomainMisconfigurationScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = CrossDomainMisconfigurationScanRule()

    def test_no_cors_header(self):
        self.response.headers = {}
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_cors_allow_origin_wildcard(self):
        self.response.headers = {
            'Access-Control-Allow-Origin': '*'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assertIsInstance(result, Alert)

    def test_cors_allow_origin_specific_domain(self):
        self.response.headers = {
            'Access-Control-Allow-Origin': 'https://example.com'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_exception(self):
        self.response.headers = {'Access-Control-Allow-Origin': '*'}
        self.response.content = b'Some content'
        
        # Simulate an exception
        self.scan_rule.check_risk = Mock(side_effect=Exception("Test exception"))
        try:
            result = self.scan_rule.check_risk(self.request, self.response)
        except Exception as e:
            result = ScanError(description=str(e), msg_ref=self.scan_rule.MSG_REF)
        self.assertIsInstance(result, ScanError)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 264)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 14)

if __name__ == '__main__':
    unittest.main()
