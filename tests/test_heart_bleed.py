import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from src.passive_scan.passive_scan_rules.heart_bleed_scan_rule import HeartBleedScanRule
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.utils.common_alert_tag import CommonAlertTag
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest

class TestHeartBleedScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = HeartBleedScanRule()

    def test_check_risk_with_vulnerable_version(self):
        self.response.headers = {
            'Server': 'Apache/2.4.1 (Unix) OpenSSL/1.0.1e'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_HIGH, Confidence.CONFIDENCE_LOW)

    def test_check_risk_with_non_vulnerable_version(self):
        self.response.headers = {
            'Server': 'Apache/2.4.1 (Unix) OpenSSL/1.0.2g'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_with_no_openssl_version(self):
        self.response.headers = {
            'Server': 'Apache/2.4.1 (Unix)'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_with_exception(self):
        self.response.headers = Mock(side_effect=Exception("Test exception"))
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 119)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 20)

if __name__ == '__main__':
    unittest.main()
