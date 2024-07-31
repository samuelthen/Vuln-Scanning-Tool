import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.insecure_authentication_scan_rule import InsecureAuthenticationScanRule

class TestInsecureAuthenticationScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = InsecureAuthenticationScanRule()

    def test_check_risk_secure_request(self):
        self.request.url = 'https://example.com'
        self.request.headers = {
            'Authorization': 'Basic dXNlcm5hbWU6cGFzc3dvcmQ='
        }
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_basic_auth(self):
        self.request.url = 'http://example.com'
        self.request.headers = {
            'Authorization': 'Basic dXNlcm5hbWU6cGFzc3dvcmQ='  # "username:password" base64 encoded
        }
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_HIGH, Confidence.CONFIDENCE_MEDIUM)

    def test_check_risk_basic_auth_no_password(self):
        self.request.url = 'http://example.com'
        self.request.headers = {
            'Authorization': 'Basic dXNlcm5hbWU='  # "username" base64 encoded
        }
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_MEDIUM)

    def test_check_risk_digest_auth(self):
        self.request.url = 'http://example.com'
        self.request.headers = {
            'Authorization': 'Digest username="admin", realm="testrealm@host.com", ...'
        }
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_MEDIUM)

    def test_check_risk_malformed_basic_auth(self):
        self.request.url = 'http://example.com'
        self.request.headers = {
            'Authorization': 'Basic bad_base64_value'
        }
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_check_risk_no_auth_header(self):
        self.request.url = 'http://example.com'
        self.request.headers = {}
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_exception(self):
        self.request.url = 'http://example.com'
        self.request.headers = Mock(side_effect=Exception("Test exception"))
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 326)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 4)

if __name__ == '__main__':
    unittest.main()
