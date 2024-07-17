import unittest
from unittest.mock import Mock, patch
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.content_type_missing_scan_rule import ContentTypeMissingScanRule

class TestContentTypeMissingScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = ContentTypeMissingScanRule()

    def test_check_risk_missing_content_type(self):
        self.response.headers = {
            'Content-Length': '123'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)

    def test_check_risk_empty_content_type(self):
        self.response.headers = {
            'Content-Type': '',
            'Content-Length': '123'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)

    def test_check_risk_valid_content_type(self):
        self.response.headers = {
            'Content-Type': 'text/html',
            'Content-Length': '123'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_no_content(self):
        self.response.headers = {
            'Content-Type': 'text/html',
            'Content-Length': '0'
        }
        self.response.content = b''

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_scan_error(self):
        self.response.headers = []
        self.response.content = b"Some content"

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assertIsInstance(result, ScanError)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 345)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 12)

if __name__ == '__main__':
    unittest.main()
