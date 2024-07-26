import unittest
from unittest.mock import Mock, patch
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.user_controlled_open_redirect_scan_rule import UserControlledOpenRedirectScanRule

class TestUserControlledOpenRedirectScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = UserControlledOpenRedirectScanRule()

    def test_check_risk_no_redirect(self):
        self.response.status_code = 200
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_safe_redirect(self):
        self.response.status_code = 302
        self.response.headers['Location'] = 'https://example.com/safe'
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_user_controlled_redirect(self):
        self.request.params = {'redirect': 'https://malicious.com'}
        self.response.status_code = 302
        self.response.headers['Location'] = 'https://malicious.com'
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_HIGH, Confidence.CONFIDENCE_MEDIUM)

    def test_check_risk_user_controlled_redirect_in_path(self):
        self.request.params = {'redirect': 'evil.com'}
        self.response.status_code = 301
        self.response.headers['Location'] = 'https://example.com/path/evil.com'
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_HIGH, Confidence.CONFIDENCE_MEDIUM)

    def test_check_risk_user_controlled_redirect_in_post_data(self):
        self.request.data = {'redirect': 'https://malicious.com'}
        self.response.status_code = 302
        self.response.headers['Location'] = 'https://malicious.com'
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_HIGH, Confidence.CONFIDENCE_MEDIUM)

    def test_check_risk_exception(self):
        self.response.status_code = 302
        self.response.headers = Mock(side_effect=Exception("Test exception"))
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_is_user_controlled_redirect_true(self):
        location = 'https://malicious.com'
        params = {'redirect': 'https://malicious.com'}
        self.assertTrue(self.scan_rule.is_user_controlled_redirect(location, params))

    def test_is_user_controlled_redirect_false(self):
        location = 'https://example.com/safe'
        params = {'redirect': 'https://malicious.com'}
        self.assertFalse(self.scan_rule.is_user_controlled_redirect(location, params))

    def test_is_user_controlled_redirect_partial_match(self):
        location = 'https://example.com/path/malicious.com'
        params = {'redirect': 'malicious.com'}
        self.assertTrue(self.scan_rule.is_user_controlled_redirect(location, params))

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 601)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 38)

if __name__ == '__main__':
    unittest.main()