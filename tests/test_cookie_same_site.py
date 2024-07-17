import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from src.passive_scan.passive_scan_rules.cookie_same_site_scan_rule import CookieSameSiteScanRule
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest

class TestCookieSameSiteScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = CookieSameSiteScanRule()

    def test_no_cookies(self):
        self.response.headers = {}
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_cookie_missing_samesite(self):
        self.response.headers = {
            'Set-Cookie': 'sessionid=abc123; Secure; HttpOnly'
        }
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)
        self.assertIn("Missing SameSite attribute in cookie", result.description)

    def test_cookie_samesite_none(self):
        self.response.headers = {
            'Set-Cookie': 'sessionid=abc123; Secure; HttpOnly; SameSite=None'
        }
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)
        self.assertIn("SameSite attribute set to None in cookie", result.description)

    def test_cookie_samesite_strict(self):
        self.response.headers = {
            'Set-Cookie': 'sessionid=abc123; Secure; HttpOnly; SameSite=Strict'
        }
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_cookie_samesite_lax(self):
        self.response.headers = {
            'Set-Cookie': 'sessionid=abc123; Secure; HttpOnly; SameSite=Lax'
        }
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_cookie_invalid_samesite(self):
        self.response.headers = {
            'Set-Cookie': 'sessionid=abc123; Secure; HttpOnly; SameSite=InvalidValue'
        }
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)
        self.assertIn("SameSite attribute has an illegal value in cookie", result.description)

    def test_multiple_cookies(self):
        self.response.headers = {
            'Set-Cookie': 'sessionid=abc123; Secure; HttpOnly; SameSite=Lax, csrftoken=xyz456; Secure; HttpOnly'
        }
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)
        self.assertIn("Missing SameSite attribute in cookie", result.description)

    def test_check_risk_exception(self):
        self.response.headers = {'Set-Cookie': 'sessionid=abc123; Secure; HttpOnly; SameSite=Lax'}
        
        # Simulate an exception
        self.response.headers = Mock(side_effect=Exception("Test exception"))

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 1275)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 13)

if __name__ == '__main__':
    unittest.main()

