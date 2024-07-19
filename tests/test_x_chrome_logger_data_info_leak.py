import unittest
from unittest.mock import Mock
import base64
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.x_chrome_logger_data_info_leak_scan_rule import XChromeLoggerDataInfoLeakScanRule
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk

class TestXChromeLoggerDataInfoLeakScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = XChromeLoggerDataInfoLeakScanRule()

    def test_check_risk_with_x_chromelogger_data_header(self):
        self.response.headers = {
            'X-ChromeLogger-Data': base64.b64encode(b'Some logger data').decode('utf-8')
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assertIsInstance(result, Alert)
        self.assertEqual(result.risk_category, Risk.RISK_MEDIUM)
        self.assertEqual(result.confidence, Confidence.CONFIDENCE_HIGH)
        self.assertIn('Decoded header value', result.other_info)

    def test_check_risk_with_x_chromephp_data_header(self):
        self.response.headers = {
            'X-ChromePhp-Data': base64.b64encode(b'Some PHP logger data').decode('utf-8')
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assertIsInstance(result, Alert)
        self.assertEqual(result.risk_category, Risk.RISK_MEDIUM)
        self.assertEqual(result.confidence, Confidence.CONFIDENCE_HIGH)
        self.assertIn('Decoded header value', result.other_info)

    def test_check_risk_without_logger_headers(self):
        self.response.headers = {
            'Content-Type': 'text/html'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_with_invalid_base64_header(self):
        self.response.headers = {
            'X-ChromeLogger-Data': 'InvalidBase64'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assertIsInstance(result, Alert)
        self.assertEqual(result.risk_category, Risk.RISK_MEDIUM)
        self.assertEqual(result.confidence, Confidence.CONFIDENCE_HIGH)
        self.assertIn('Failed to decode header value', result.other_info)

    def test_check_risk_with_exception(self):
        self.response.headers = Mock()
        self.response.headers.get.side_effect = Exception("Test exception")
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 200)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 13)

if __name__ == '__main__':
    unittest.main()
