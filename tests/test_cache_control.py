import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.cache_control_scan_rule import CacheControlScanRule

class TestCacheControlScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = CacheControlScanRule()

    def test_check_risk_secure_request_with_proper_headers(self):
        self.request.url = 'https://example.com'
        self.response.headers = {
            'Content-Type': 'text/html',
            'Cache-Control': 'no-store, no-cache, must-revalidate'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_secure_request_with_improper_headers(self):
        self.request.url = 'https://example.com'
        self.response.headers = {
            'Content-Type': 'text/html',
            'Cache-Control': 'public, max-age=3600'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_LOW)

    def test_check_risk_insecure_request(self):
        self.request.url = 'http://example.com'
        self.response.headers = {
            'Content-Type': 'text/html',
            'Cache-Control': 'public, max-age=3600'
        }
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_empty_response(self):
        self.request.url = 'https://example.com'
        self.response.headers = {
            'Content-Type': 'text/html',
            'Cache-Control': 'public, max-age=3600'
        }
        self.response.content = b''

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_image_content(self):
        self.request.url = 'https://example.com'
        self.response.headers = {
            'Content-Type': 'image/jpeg',
            'Cache-Control': 'public, max-age=3600'
        }
        self.response.content = b'Image content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_non_html_response(self):
        self.request.url = 'https://example.com'  # Override for HTTPS
        self.response.headers['Content-Type'] = 'application/javascript'
        self.response.headers['Cache-Control'] = 'public, max-age=3600'  # Improper for sensitive content, but should be ignored
        self.response.content = b'console.log("Hello, World!");'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_exception(self):
        self.request.url = 'https://example.com'
        self.response.headers = {'Content-Type': 'text/html'}
        self.response.content = b'Some content'
        
        # Simulate an exception
        self.response.headers = Mock(side_effect=Exception("Test exception"))

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)
        
    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 525)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 13)

if __name__ == '__main__':
    unittest.main()