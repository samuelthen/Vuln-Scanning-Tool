import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.information_disclosure_in_url_scan_rule import InformationDisclosureInUrlScanRule

class TestInformationDisclosureInUrlScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = InformationDisclosureInUrlScanRule()

    def test_check_risk_no_sensitive_info(self):
        self.request.params = {'param1': 'value1', 'param2': 'value2'}
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_sensitive_param_name(self):
        self.request.params = {'username': 'john_doe'}
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)

    def test_check_risk_credit_card(self):
        self.request.params = {'card': '4111111111111111'}
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)
        self.assertIn('Credit card number found in URL parameter', result.description)

    def test_check_risk_email_address(self):
        self.request.params = {'email': 'test@example.com'}
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)
        self.assertIn('Email address found in URL parameter', result.description)

    def test_check_risk_us_ssn(self):
        self.request.params = {'ssn': '123-45-6789'}
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)
        self.assertIn('US Social Security Number found in URL parameter', result.description)

    def test_check_risk_exception(self):
        self.request.params = Mock(side_effect=Exception("Test exception"))
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_contains_sensitive_information(self):
        self.assertTrue(self.scan_rule.contains_sensitive_information('username'))
        self.assertTrue(self.scan_rule.contains_sensitive_information('password'))
        self.assertFalse(self.scan_rule.contains_sensitive_information('normal_param'))

    def test_is_email_address(self):
        self.assertTrue(self.scan_rule.is_email_address('test@example.com'))
        self.assertFalse(self.scan_rule.is_email_address('not_an_email'))

    def test_is_credit_card(self):
        self.assertTrue(self.scan_rule.is_credit_card('4111111111111111'))
        self.assertFalse(self.scan_rule.is_credit_card('1234567890'))

    def test_is_us_ssn(self):
        self.assertTrue(self.scan_rule.is_us_ssn('123-45-6789'))
        self.assertFalse(self.scan_rule.is_us_ssn('12345-6789'))

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 200)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 13)

if __name__ == '__main__':
    unittest.main()