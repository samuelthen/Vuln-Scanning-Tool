import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.user_controlled_charset_scan_rule import UserControlledCharsetScanRule

class TestUserControlledCharsetScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = UserControlledCharsetScanRule()
        self.request = Mock(spec=Request)
        self.response = Mock(spec=Response)
        self.request.url = 'http://example.com/?charset=utf-8'

    def test_no_params(self):
        self.request.url = 'http://example.com/'
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assertIsInstance(result, NoAlert)

    def test_proper_charset_in_content_type(self):
        self.response.headers = {'Content-Type': 'text/html; charset=utf-8'}
        self.response.text = '<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body></body></html>'
        self.request.url = 'http://example.com/?charset=iso-8859-1'
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assertIsInstance(result, NoAlert)

    def test_user_controlled_charset_in_content_type(self):
        self.response.headers = {'Content-Type': 'text/html; charset=utf-8'}
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assertIsInstance(result, Alert)
        self.assertEqual(result.risk_category, Risk.RISK_INFO)
        self.assertEqual(result.confidence, Confidence.CONFIDENCE_LOW)

    def test_proper_meta_charset(self):
        self.response.headers = {'Content-Type': 'text/html'}
        self.response.text = '<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body></body></html>'
        self.request.url = 'http://example.com/?charset=iso-8859-1'
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assertIsInstance(result, NoAlert)

    def test_user_controlled_meta_charset(self):
        self.response.headers = {'Content-Type': 'text/html'}
        self.response.text = '<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body></body></html>'
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assertIsInstance(result, Alert)
        self.assertEqual(result.risk_category, Risk.RISK_INFO)
        self.assertEqual(result.confidence, Confidence.CONFIDENCE_LOW)

    def test_proper_xml_encoding(self):
        self.response.headers = {'Content-Type': 'application/xml'}
        self.response.text = '<?xml version="1.0" encoding="utf-8"?><root></root>'
        self.request.url = 'http://example.com/?charset=iso-8859-1'
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assertIsInstance(result, NoAlert)

    def test_user_controlled_xml_encoding(self):
        self.response.headers = {'Content-Type': 'application/xml'}
        self.response.text = '<?xml version="1.0" encoding="utf-8"?><root></root>'
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assertIsInstance(result, Alert)
        self.assertEqual(result.risk_category, Risk.RISK_INFO)
        self.assertEqual(result.confidence, Confidence.CONFIDENCE_LOW)

    def test_check_risk_empty_response(self):
        self.response.headers = {'Content-Type': 'text/html'}
        self.response.text = ''
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assertIsInstance(result, NoAlert)

    def test_check_risk_non_html_response(self):
        self.response.headers = {'Content-Type': 'application/javascript'}
        self.response.text = 'console.log("Hello, World!");'
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assertIsInstance(result, NoAlert)

    def test_check_risk_exception(self):
        self.response.headers = {'Content-Type': 'text/html'}
        self.response.text = '<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body></body></html>'
        self.request.url = Mock(side_effect=Exception("Test exception"))

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assertIsInstance(result, ScanError)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 20)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 20)

if __name__ == '__main__':
    unittest.main()
