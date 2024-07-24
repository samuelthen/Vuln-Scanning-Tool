import unittest
from unittest.mock import Mock, patch
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.mixed_content_scan_rule import MixedContentScanRule

class TestMixedContentScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = MixedContentScanRule()

    def test_check_risk_secure_request_no_mixed_content(self):
        self.request.url = 'https://example.com'
        self.set_response_content('<img src="https://secure.example.com/image.jpg">')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_secure_request_with_mixed_content(self):
        self.request.url = 'https://example.com'
        self.set_response_content('<img src="http://insecure.example.com/image.jpg">')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)

    def test_check_risk_secure_request_with_mixed_script_content(self):
        self.request.url = 'https://example.com'
        self.set_response_content('<script src="http://insecure.example.com/script.js"></script>')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_MEDIUM)

    def test_check_risk_insecure_request(self):
        self.request.url = 'http://example.com'
        self.set_response_content('<img src="http://insecure.example.com/image.jpg">')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_non_html_response(self):
        self.request.url = 'https://example.com'
        self.set_response_content('{"key": "value"}', content_type='application/json')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_multiple_mixed_content(self):
        self.request.url = 'https://example.com'
        self.set_response_content('''
            <img src="http://insecure1.example.com/image.jpg">
            <script src="http://insecure2.example.com/script.js"></script>
            <link rel="stylesheet" href="http://insecure3.example.com/style.css">
        ''')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_MEDIUM)

    def test_check_risk_mixed_content_in_various_attributes(self):
        self.request.url = 'https://example.com'
        self.set_response_content('''
            <div background="http://insecure.example.com/bg.jpg"></div>
            <object classid="http://insecure.example.com/class"></object>
            <object codebase="http://insecure.example.com/base"></object>
            <object data="http://insecure.example.com/data"></object>
            <link rel="icon" href="http://insecure.example.com/icon.ico">
            <img src="image.jpg" usemap="http://insecure.example.com/map">
            <form action="http://insecure.example.com/submit"></form>
            <button formaction="http://insecure.example.com/submit"></button>
        ''')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)

    @patch('src.passive_scan.passive_scan_rules.mixed_content_scan_rule.BeautifulSoup')
    def test_check_risk_exception(self, mock_bs):
        self.request.url = 'https://example.com'
        self.set_response_content('<html><body>Test</body></html>')
        mock_bs.side_effect = Exception("Test exception")

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 311)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 4)

if __name__ == '__main__':
    unittest.main()