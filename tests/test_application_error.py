import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from src.passive_scan.passive_scan_rules.application_error_scan_rule import ApplicationErrorScanRule
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest

class TestApplicationErrorScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = ApplicationErrorScanRule()

    def test_check_risk_internal_server_error(self):
        self.response.status_code = 500
        self.response.text = 'Internal Server Error'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_MEDIUM)

    def test_check_risk_non_html_response(self):
        self.response.headers['Content-Type'] = 'application/json'
        self.response.text = '{"message": "Not Found"}'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_404_response(self):
        self.response.status_code = 404
        self.response.headers['Content-Type'] = 'text/html'
        self.response.text = 'Not Found'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_wasm_response(self):
        self.response.headers['Content-Type'] = 'application/wasm'
        self.response.text = 'wasm content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_custom_payload(self):
        self.response.headers['Content-Type'] = 'text/html'
        self.response.text = 'Custom error occurred'

        self.scan_rule.payload_provider = lambda: ['Custom error occurred']

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_MEDIUM)

    def test_check_risk_pattern_match(self):
        self.response.headers['Content-Type'] = 'text/html'
        self.response.text = 'ERROR: parser: parse error at or near'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_MEDIUM)

    def test_check_risk_no_match(self):
        self.response.headers['Content-Type'] = 'text/html'
        self.response.text = 'Normal content without errors'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_exception(self):
        self.response.headers = Mock(side_effect=Exception("Test exception"))
        self.response.text = 'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 200)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 13)

if __name__ == '__main__':
    unittest.main()
