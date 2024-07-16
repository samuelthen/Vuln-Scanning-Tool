import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.charset_mismatch_scan_rule import CharsetMismatchScanRule

class TestCharsetMismatchScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = CharsetMismatchScanRule()

    def test_no_charset_in_header(self):
        self.response.headers = {
            'Content-Type': 'text/html'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_matching_charset_in_meta(self):
        self.response.headers = {
            'Content-Type': 'text/html; charset=UTF-8'
        }
        self.response.content = b'<html><head><meta charset="UTF-8"></head><body>Some content</body></html>'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_mismatched_charset_in_meta(self):
        self.response.headers = {
            'Content-Type': 'text/html; charset=UTF-8'
        }
        self.response.content = b'<html><head><meta charset="ISO-8859-1"></head><body>Some content</body></html>'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assertIsInstance(result, Alert)
        self.assertEqual(result.evidence, 'Charset mismatch: header=UTF-8, body=ISO-8859-1')

    def test_matching_charset_in_xml(self):
        self.response.headers = {
            'Content-Type': 'application/xml; charset=UTF-8'
        }
        self.response.content = b'<?xml version="1.0" encoding="UTF-8"?><root>Some content</root>'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_mismatched_charset_in_xml(self):
        self.response.headers = {
            'Content-Type': 'application/xml; charset=UTF-8'
        }
        self.response.content = b'<?xml version="1.0" encoding="ISO-8859-1"?><root>Some content</root>'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assertIsInstance(result, Alert)
        self.assertEqual(result.evidence, 'Charset mismatch: header=UTF-8, body=ISO-8859-1')

    def test_check_risk_exception(self):
        self.response.headers = {'Content-Type': 'text/html; charset=UTF-8'}
        self.response.content = b'Some content'
        
        # Simulate an exception
        self.scan_rule.extract_meta_charset = Mock(side_effect=Exception("Test exception"))

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 436)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 15)

if __name__ == '__main__':
    unittest.main()
