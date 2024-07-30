import hashlib
import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.username_idor_scan_rule import UsernameIdorScanRule
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest

class TestUsernameIdorScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = UsernameIdorScanRule()

    def test_check_risk_no_users(self):
        self.scan_rule.payload_provider = Mock(return_value=[])
        self.response.text = 'Some response content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_user_in_response(self):
        self.scan_rule.payload_provider = Mock(return_value=['admin'])
        self.response.text = 'Response content with admin'
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_HIGH)

    def test_check_risk_user_hash_in_response(self):
        self.scan_rule.payload_provider = Mock(return_value=['admin'])
        admin_hash_md5 = hashlib.md5('admin'.encode()).hexdigest()
        self.response.text = f'Response content with hash {admin_hash_md5}'
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_HIGH)

    def test_check_risk_no_user_in_response(self):
        self.scan_rule.payload_provider = Mock(return_value=['admin'])
        self.response.text = 'Some response content without user'
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_exception(self):
        self.scan_rule.payload_provider = Mock(side_effect=Exception("Test exception"))
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)
        
    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 284)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 2)

if __name__ == '__main__':
    unittest.main()
