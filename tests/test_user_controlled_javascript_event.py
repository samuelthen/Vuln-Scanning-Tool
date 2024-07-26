import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.user_controlled_javascript_event_scan_rule import UserControlledJavascriptEventScanRule

class TestUserControlledJavascriptEventScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = UserControlledJavascriptEventScanRule()

    def test_check_risk_no_javascript_events(self):
        self.request.url = 'https://example.com'
        self.set_response_content('<html><body><p>No JavaScript events here</p></body></html>')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_javascript_event_no_user_input(self):
        self.request.url = 'https://example.com'
        self.set_response_content('<html><body><button onclick="alert(\'Hello\')">Click me</button></body></html>')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_javascript_event_with_user_input(self):
        self.request.url = 'https://example.com?user_input=test'
        self.set_response_content('<html><body><button onclick="alert(\'test\')">Click me</button></body></html>')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_LOW)

    def test_check_risk_multiple_javascript_events(self):
        self.request.url = 'https://example.com?param1=test1&param2=test2'
        self.set_response_content('''
            <html>
                <body>
                    <button onclick="alert('test1')">Button 1</button>
                    <div onmouseover="console.log('test2')">Hover me</div>
                </body>
            </html>
        ''')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_LOW)

    def test_check_risk_non_html_response(self):
        self.request.url = 'https://example.com?param=test'
        self.set_response_content('{"key": "value"}', content_type='application/json')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_exception(self):
        self.request.url = 'https://example.com'
        self.response.text = Mock(side_effect=Exception("Test exception"))

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_get_parameters(self):
        url = 'https://example.com?param1=value1&param2=value2&param3=value3'
        params = self.scan_rule.get_parameters(url)
        self.assertEqual(params, {'value1', 'value2', 'value3'})

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 20)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 20)


if __name__ == '__main__':
    unittest.main()