import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from bs4 import BeautifulSoup
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.insecure_form_load_scan_rule import InsecureFormLoadScanRule
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest

class TestInsecureFormLoadScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = InsecureFormLoadScanRule()

    def test_check_risk_http_page_with_https_form(self):
        self.request.url = 'http://example.com'
        self.set_response_content('<form action="https://secure.example.com/submit">...</form>')
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_MEDIUM)
        self.assertIn("Form action uses HTTPS while the page is served over HTTP", result.description)

    def test_check_risk_http_page_with_http_form(self):
        self.request.url = 'http://example.com'
        self.set_response_content('<form action="http://example.com/submit">...</form>')
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_https_page(self):
        self.request.url = 'https://example.com'
        self.set_response_content('<form action="https://example.com/submit">...</form>')
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_non_html_response(self):
        self.request.url = 'http://example.com'
        self.set_response_content('{"key": "value"}', content_type='application/json')
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_empty_response(self):
        self.request.url = 'http://example.com'
        self.set_response_content('')
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_multiple_forms(self):
        self.request.url = 'http://example.com'
        self.set_response_content('''
            <form action="http://example.com/submit1">...</form>
            <form action="https://secure.example.com/submit2">...</form>
            <form action="http://example.com/submit3">...</form>
        ''')
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_MEDIUM)

    def test_check_risk_relative_form_action(self):
        self.request.url = 'http://example.com'
        self.set_response_content('<form action="/submit">...</form>')
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_exception_handling(self):
        self.request.url = 'http://example.com'
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

    def test_str_representation(self):
        self.assertEqual(str(self.scan_rule), "Insecure Form Load Scan Rule")

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 319)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 15)

if __name__ == '__main__':
    unittest.main()