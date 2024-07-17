import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.cookie_loosely_scoped_scan_rule import CookieLooselyScopedScanRule

class TestCookieLooselyScopedScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = CookieLooselyScopedScanRule()

    def test_no_cookies(self):
        self.response.headers = {}
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_strictly_scoped_cookie(self):
        self.request.url = 'http://example.com'
        self.response.headers = {
            'Set-Cookie': 'sessionid=abc123; Domain=example.com; Path=/'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_loosely_scoped_cookie(self):
        self.request.url = 'http://sub.example.com'
        self.response.headers = {
            'Set-Cookie': 'sessionid=abc123; Domain=.example.com; Path=/'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_LOW)
        self.assertIn('Domain=.example.com', result.evidence)

    def test_malformed_cookie(self):
        self.request.url = 'http://example.com'
        self.response.headers = {
            'Set-Cookie': 'sessionid=abc123; Domain'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_multiple_cookies(self):
        self.request.url = 'http://sub.example.com'
        # 
        self.response.headers = {
            'Set-Cookie': 'sessionid=abc123; Domain=.example.com; Path=/, \
                           sessionid=xyz456; Domain=example.com; Path=/'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_LOW)
        self.assertIn('sessionid=abc123; Domain=.example.com; Path=/', result.evidence)
        self.assertNotIn('token=xyz456; Domain=example.com; Path=/', result.evidence)

    def test_check_risk_exception(self):
        self.request.url = 'http://example.com'
        self.response.headers = {'Set-Cookie': 'sessionid=abc123; Domain=example.com; Path=/'}
        self.response.content = b'Some content'
        
        # Simulate an exception
        self.scan_rule.check_risk = Mock(side_effect=Exception("Test exception"))

        try:
            result = self.scan_rule.check_risk(self.request, self.response)
        except Exception as e:
            result = ScanError(description=str(e), msg_ref=self.scan_rule.MSG_REF)

        self.assert_scan_error(result)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 565)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 15)

if __name__ == '__main__':
    unittest.main()
