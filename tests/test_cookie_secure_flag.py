import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.cookie_secure_flag_scan_rule import CookieSecureFlagScanRule

class TestCookieSecureFlagScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = CookieSecureFlagScanRule()

    def test_check_risk_secure_request_with_secure_cookie(self):
        self.request.url = 'https://example.com'
        self.response.headers = {
            'Set-Cookie': 'sessionid=abc123; Secure; HttpOnly',
            'Content-Type': 'text/html'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_secure_request_without_secure_cookie(self):
        self.request.url = 'https://example.com'
        self.response.headers = {
            'Set-Cookie': 'sessionid=abc123; HttpOnly',
            'Content-Type': 'text/html'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)

    def test_check_risk_secure_request_no_cookie(self):
        self.request.url = 'https://example.com'
        self.response.headers = {
            'Content-Type': 'text/html'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_insecure_request(self):
        self.request.url = 'http://example.com'
        self.response.headers = {
            'Set-Cookie': 'sessionid=abc123; HttpOnly',
            'Content-Type': 'text/html'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_exception(self):
        self.request.url = 'https://example.com'
        self.response.headers = {
            'Set-Cookie': 'sessionid=abc123; HttpOnly',
            'Content-Type': 'text/html'
        }
        self.response.content = b'Some content'
        
        # Simulate an exception
        self.response.headers = Mock(side_effect=Exception("Test exception"))

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 614)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 13)

if __name__ == '__main__':
    unittest.main()
