import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.info_private_address_disclosure_scan_rule import InfoPrivateAddressDisclosureScanRule
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk

class TestInfoPrivateAddressDisclosureScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = InfoPrivateAddressDisclosureScanRule()

    def test_private_ip_disclosure(self):
        self.response.text = 'This is a sample response with a private IP 192.168.1.1 in the content.'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)
        self.assertIn('192.168.1.1', result.evidence)

    def test_no_private_ip_disclosure(self):
        self.response.text = 'This is a sample response without any private IP.'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_private_ip_disclosure_in_dashed_format(self):
        self.response.text = 'This is a sample response with a private IP ip-192-168-1-1 in the content.'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)
        self.assertIn('ip-192-168-1-1', result.evidence)

    def test_private_ip_disclosure_multiple(self):
        self.response.text = 'Private IPs in content: 10.0.0.1 and 192.168.1.1.'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)
        self.assertIn('10.0.0.1', result.evidence)
        self.assertIn('192.168.1.1', result.evidence)

    def test_private_ip_disclosure_ignored_host(self):
        self.request.headers['Host'] = '10.0.0.1'
        self.response.text = 'Response with private IP same as host 10.0.0.1.'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_exception(self):
        self.response.text = Mock(side_effect=Exception("Test exception"))

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 200)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 13)

if __name__ == '__main__':
    unittest.main()
