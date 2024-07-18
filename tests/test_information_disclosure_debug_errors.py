import unittest
from unittest.mock import Mock, patch
from requests.models import Request, Response
from src.passive_scan.passive_scan_rules.information_disclosure_debug_errors_scan_rule import InformationDisclosureDebugErrorsScanRule
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest

class TestInformationDisclosureDebugErrorsScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = InformationDisclosureDebugErrorsScanRule()

    @patch('src.passive_scan.passive_scan_rules.information_disclosure_debug_errors_scan_rule.InformationDisclosureDebugErrorsScanRule.load_errors')
    def test_check_risk_with_debug_error_message(self, mock_load_errors):
        self.set_response_content('This is a test response with a PHP error.')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)

    @patch('src.passive_scan.passive_scan_rules.information_disclosure_debug_errors_scan_rule.InformationDisclosureDebugErrorsScanRule.load_errors')
    def test_check_risk_without_debug_error_message(self, mock_load_errors):
        self.set_response_content('This is a test response without any errors.')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_with_non_text_content_type(self):
        self.response.headers['Content-Type'] = 'application/octet-stream'
        self.set_response_content('This is a binary response.')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    @patch('src.passive_scan.passive_scan_rules.information_disclosure_debug_errors_scan_rule.InformationDisclosureDebugErrorsScanRule.load_errors')
    def test_check_risk_with_exception(self, mock_load_errors):
        mock_load_errors.return_value = ['debug error']
        self.set_response_content('This is a test response with a debug error.')

        # Simulate an exception during the scan by patching the response object's text property to raise an exception
        with patch.object(self.response, 'text', new_callable=Mock, side_effect=Exception("Test exception")):
            result = self.scan_rule.check_risk(self.request, self.response)
            self.assert_scan_error(result)

    @patch('src.passive_scan.passive_scan_rules.information_disclosure_debug_errors_scan_rule.InformationDisclosureDebugErrorsScanRule.load_errors')
    def test_check_risk_empty_response(self, mock_load_errors):
        mock_load_errors.return_value = ['debug error']
        self.set_response_content('')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 200)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 13)

if __name__ == '__main__':
    unittest.main()
