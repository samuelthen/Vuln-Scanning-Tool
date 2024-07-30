import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.user_controlled_cookie_scan_rule import UserControlledCookieScanRule

class TestUserControlledCookieScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = UserControlledCookieScanRule()
        self.request = Mock(spec=Request)
        self.response = Mock(spec=Response)
        self.request.params = {}
        self.request.data = {}
        self.response.encoding = 'utf-8'  # Adding the encoding attribute

    def test_check_risk_no_cookies(self):
        self.response.headers = {}
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_no_params(self):
        self.response.headers = {'Set-Cookie': 'session=abc123'}
        self.request.params = {}
        self.request.data = {}
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_user_controlled_cookie(self):
        self.response.headers = {'Set-Cookie': 'session=uservalue'}
        self.request.params = {'user_input': 'uservalue'}
        self.request.data = {}
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_LOW)

    def test_check_risk_non_matching_cookie(self):
        self.response.headers = {'Set-Cookie': 'session=abc123'}
        self.request.params = {'user_input': 'uservalue'}
        self.request.data = {}
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_multiple_cookies(self):
        self.response.headers = {'Set-Cookie': 'session=abc123; user=uservalue'}
        self.request.params = {'user_input': 'uservalue'}
        self.request.data = {}
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_LOW)

    def test_check_risk_encoded_cookie(self):
        self.response.headers = {'Set-Cookie': 'session=user%20value'}
        self.request.params = {'user_input': 'user value'}
        self.request.data = {}
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_LOW)

    def test_check_risk_exception(self):
        self.response.headers = Mock()
        self.response.headers.get.side_effect = Exception("Test exception")
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 565)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 20)

if __name__ == '__main__':
    unittest.main()
