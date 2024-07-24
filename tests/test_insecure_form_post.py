import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.insecure_form_post_scan_rule import InsecureFormPostScanRule

class TestInsecureFormPostScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = InsecureFormPostScanRule()

    def test_check_risk_secure_request_with_secure_form(self):
        self.request.url = 'https://example.com'
        self.set_response_content('<form action="https://secure.example.com/submit"></form>')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_secure_request_with_insecure_form(self):
        self.request.url = 'https://example.com'
        self.set_response_content('<form action="http://insecure.example.com/submit"></form>')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_MEDIUM)

    def test_check_risk_insecure_request(self):
        self.request.url = 'http://example.com'
        self.set_response_content('<form action="http://insecure.example.com/submit"></form>')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_non_html_response(self):
        self.request.url = 'https://example.com'
        self.set_response_content('{"key": "value"}', content_type='application/json')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_empty_response(self):
        self.request.url = 'https://example.com'
        self.set_response_content('')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_multiple_forms(self):
        self.request.url = 'https://example.com'
        self.set_response_content('''
            <form action="https://secure1.example.com/submit"></form>
            <form action="http://insecure.example.com/submit"></form>
            <form action="https://secure2.example.com/submit"></form>
        ''')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_MEDIUM)

    def test_check_risk_relative_form_action(self):
        self.request.url = 'https://example.com'
        self.set_response_content('<form action="/submit"></form>')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_exception(self):
        self.request.url = 'https://example.com'
        self.response.text = Mock(side_effect=Exception("Test exception"))

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_is_response_html(self):
        self.response.headers = {'Content-Type': 'text/html'}
        self.assertTrue(self.scan_rule.is_response_html(self.response))

        self.response.headers = {'Content-Type': 'application/xhtml+xml'}
        self.assertTrue(self.scan_rule.is_response_html(self.response))

        self.response.headers = {'Content-Type': 'application/json'}
        self.assertFalse(self.scan_rule.is_response_html(self.response))

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 319)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 15)


if __name__ == '__main__':
    unittest.main()