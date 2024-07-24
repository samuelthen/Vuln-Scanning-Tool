import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.user_controlled_html_attributes_scan_rule import UserControlledHTMLAttributesScanRule

class TestUserControlledHTMLAttributesScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = UserControlledHTMLAttributesScanRule()

    def test_check_risk_no_html_content(self):
        self.response.headers = {'Content-Type': 'application/json'}
        self.response.text = '{"key": "value"}'
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_no_parameters(self):
        self.request.url = 'http://example.com'
        self.response.headers = {'Content-Type': 'text/html'}
        self.response.text = '<html><body><a href="safe.html">Link</a></body></html>'
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_safe_attribute(self):
        self.request.url = 'http://example.com?param=value'
        self.response.headers = {'Content-Type': 'text/html'}
        self.response.text = '<html><body><a href="safe.html">Link</a></body></html>'
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_user_controlled_attribute(self):
        self.request.url = 'http://example.com?param=value'
        self.response.headers = {'Content-Type': 'text/html'}
        self.response.text = '<html><body><a href="value.html">Link</a></body></html>'
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_LOW)

    def test_check_risk_user_controlled_protocol(self):
        self.request.url = 'http://example.com?param=http'
        self.response.headers = {'Content-Type': 'text/html'}
        self.response.text = '<html><body><a href="http://example.com">Link</a></body></html>'
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_LOW)

    def test_check_risk_user_controlled_domain(self):
        self.request.url = 'http://example.com?param=evil.com'
        self.response.headers = {'Content-Type': 'text/html'}
        self.response.text = '<html><body><a href="http://evil.com">Link</a></body></html>'
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_LOW)

    def test_check_risk_case_insensitive(self):
        self.request.url = 'http://example.com?param=VALUE'
        self.response.headers = {'Content-Type': 'text/html'}
        self.response.text = '<html><body><a href="value.html">Link</a></body></html>'
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_LOW)

    def test_check_risk_multiple_parameters(self):
        self.request.url = 'http://example.com?param1=value1&param2=value2'
        self.response.headers = {'Content-Type': 'text/html'}
        self.response.text = '<html><body><a href="value2.html">Link</a></body></html>'
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_LOW)

    def test_check_risk_exception(self):
        self.request.url = 'http://example.com?param=value'
        self.response.headers = {'Content-Type': 'text/html'}
        self.response.text = Mock(side_effect=Exception("Test exception"))
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_get_parameters(self):
        url = 'http://example.com?param1=value1&param2=value2&param3=value3'
        params = self.scan_rule.get_parameters(url)
        self.assertEqual(params, {'value1', 'value2', 'value3'})

    def test_is_potentially_harmful(self):
        self.assertTrue(self.scan_rule.is_potentially_harmful('http://evil.com', 'evil.com'))
        self.assertTrue(self.scan_rule.is_potentially_harmful('javascript:alert(1)', 'javascript'))
        self.assertFalse(self.scan_rule.is_potentially_harmful('safe.html', 'unsafe'))

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 20)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 20)
        
if __name__ == '__main__':
    unittest.main()