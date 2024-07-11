import unittest
from datetime import datetime, timedelta, timezone
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.cookie_http_only_scan_rule import CookieHttpOnlyScanRule

class TestCookieHttpOnlyScanRule(BasePassiveScanRuleTest):

    def setUp(self):
        super().setUp()
        self.scan_rule = CookieHttpOnlyScanRule()

    def test_cookie_with_httponly_flag(self):
        self.set_response_content('')
        self.response.headers['Set-Cookie'] = 'sessionId=abc123; HttpOnly'
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_cookie_without_httponly_flag(self):
        self.set_response_content('')
        self.response.headers['Set-Cookie'] = 'sessionId=abc123'
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)

    def test_multiple_cookies_some_without_httponly(self):
        self.set_response_content('')
        self.response.headers['Set-Cookie'] = ['sessionId=abc123', 'userId=xyz789; HttpOnly']
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)

    def test_all_cookies_with_httponly_flag(self):
        self.set_response_content('')
        self.response.headers['Set-Cookie'] = ['sessionId=abc123; HttpOnly', 'userId=xyz789; HttpOnly']
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)
    
    def test_expired_cookie_without_httponly_flag(self):
        self.set_response_content('')
        # Setting up an expired date with timezone-aware datetime
        expired_date = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%a, %d-%b-%Y %H:%M:%S GMT")
        self.response.headers['Set-Cookie'] = f'sessionId=abc123; expires={expired_date}'
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_non_expired_cookie_without_httponly_flag(self):
        self.set_response_content('')
        future_date = (datetime.utcnow() + timedelta(days=10)).strftime("%a, %d-%b-%Y %H:%M:%S GMT")
        self.response.headers['Set-Cookie'] = f'sessionId=abc123; expires={future_date}'
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)

    def test_scan_error(self):
        self.set_response_content('')
        self.response.headers['Set-Cookie'] = 'malformed_cookie_value'
        
        # Mocking a failure in the cookie parsing logic to simulate an error
        with unittest.mock.patch.object(self.scan_rule, 'has_attribute', side_effect=Exception('parsing error')):
            result = self.scan_rule.check_risk(self.request, self.response)
            self.assert_scan_error(result)

if __name__ == '__main__':
    unittest.main()

