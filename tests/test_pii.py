import unittest
from unittest.mock import Mock, patch
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.pii_scan_rule import PiiScanRule

class TestPiiScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = PiiScanRule()

    def test_check_risk_non_text_response(self):
        self.response.headers['Content-Type'] = 'application/json'
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_no_pii(self):
        self.set_response_content('<html><body>No PII here</body></html>')
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    @patch('src.passive_scan.passive_scan_rules.pii_scan_rule.PiiUtils.is_valid_luhn')
    @patch('src.passive_scan.passive_scan_rules.pii_scan_rule.BinList.get_singleton')
    def test_check_risk_valid_visa(self, mock_binlist, mock_is_valid_luhn):
        mock_is_valid_luhn.return_value = True
        mock_binlist.return_value.get.return_value = {'bank': 'Test Bank'}
        self.set_response_content('<html><body>Visa: 4111111111111111</body></html>')
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_HIGH, Confidence.CONFIDENCE_HIGH)
        self.assertIn('4111111111111111', result.evidence)
        self.assertIn('Visa', result.evidence)
        self.assertIn('Test Bank', result.evidence)

    @patch('src.passive_scan.passive_scan_rules.pii_scan_rule.PiiUtils.is_valid_luhn')
    @patch('src.passive_scan.passive_scan_rules.pii_scan_rule.BinList.get_singleton')
    def test_check_risk_valid_mastercard(self, mock_binlist, mock_is_valid_luhn):
        mock_is_valid_luhn.return_value = True
        mock_binlist.return_value.get.return_value = None
        self.set_response_content('<html><body>Mastercard: 5555555555554444</body></html>')
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_HIGH, Risk.RISK_MEDIUM)
        self.assertIn('5555555555554444', result.evidence)
        self.assertIn('Mastercard', result.evidence)

    @patch('src.passive_scan.passive_scan_rules.pii_scan_rule.PiiUtils.is_valid_luhn')
    def test_check_risk_invalid_card_number(self, mock_is_valid_luhn):
        mock_is_valid_luhn.return_value = False
        self.set_response_content('<html><body>Invalid: 1234567890123456</body></html>')
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_exception(self):
        self.response.text = Mock(side_effect=Exception("Test exception"))
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_get_response_body_without_styles(self):
        html_content = '''
        <html>
            <head>
                <style>
                    body { color: red; }
                </style>
            </head>
            <body style="background-color: blue;">
                <p>Test content</p>
            </body>
        </html>
        '''
        self.response.text = html_content
        result = self.scan_rule.get_response_body_without_styles(self.response)
        self.assertEqual(result.strip(), "Test content")

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 359)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 13)

if __name__ == '__main__':
    unittest.main()