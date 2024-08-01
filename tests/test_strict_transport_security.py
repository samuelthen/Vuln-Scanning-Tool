import unittest
from unittest.mock import Mock, patch
from requests.models import Request, Response
from bs4 import BeautifulSoup
from src.passive_scan.passive_scan_rules.strict_transport_security_scan_rule import StrictTransportSecurityScanRule
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest

class TestStrictTransportSecurityScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = StrictTransportSecurityScanRule()

    def test_check_risk_https_missing_header(self):
        self.request.url = 'https://example.com'
        self.response.headers = {'Content-Type': 'text/html'}
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_HIGH)
        self.assertEqual(result.description, "Strict-Transport-Security header missing")

    def test_check_risk_https_valid_header(self):
        self.request.url = 'https://example.com'
        self.response.headers = {
            'Content-Type': 'text/html',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
        }
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_https_multiple_headers(self):
        self.request.url = 'https://example.com'
        self.response.headers = {
            'Content-Type': 'text/html',
            'Strict-Transport-Security': ['max-age=31536000', 'includeSubDomains']
        }
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_HIGH)
        self.assertEqual(result.description, "Multiple Strict-Transport-Security headers found")

    def test_check_risk_https_malformed_header(self):
        self.request.url = 'https://example.com'
        self.response.headers = {
            'Content-Type': 'text/html',
            'Strict-Transport-Security': 'max-age=invalid'
        }
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_HIGH)
        self.assertEqual(result.description, "Strict-Transport-Security header missing max-age")

    def test_check_risk_https_zero_max_age(self):
        self.request.url = 'https://example.com'
        self.response.headers = {
            'Content-Type': 'text/html',
            'Strict-Transport-Security': 'max-age=0'
        }
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_HIGH)
        self.assertEqual(result.description, "Strict-Transport-Security header with max-age=0")

    def test_check_risk_http_with_header(self):
        self.request.url = 'http://example.com'
        self.response.headers = {
            'Content-Type': 'text/html',
            'Strict-Transport-Security': 'max-age=31536000'
        }
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_HIGH)
        self.assertEqual(result.description, "Strict-Transport-Security header present on non-HTTPS response")

    def test_check_risk_https_redirect(self):
        self.request.url = 'https://example.com'
        self.response.status_code = 302
        self.response.headers = {
            'Content-Type': 'text/html',
            'Location': 'https://sub.example.com'
        }
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    @patch('src.passive_scan.passive_scan_rules.strict_transport_security_scan_rule.BeautifulSoup')
    def test_check_risk_meta_tag_hsts(self, mock_bs):
        self.request.url = 'https://example.com'
        self.response.headers = {'Content-Type': 'text/html'}
        self.response.text = '<html><head><meta http-equiv="Strict-Transport-Security" content="max-age=31536000"></head></html>'
        
        mock_soup = Mock()
        mock_soup.find_all.return_value = [BeautifulSoup('<meta http-equiv="Strict-Transport-Security" content="max-age=31536000">', 'html.parser').meta]
        mock_bs.return_value = mock_soup

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_HIGH)
        self.assertEqual(result.description, "Strict-Transport-Security set via META tag")

    def test_check_risk_exception(self):
        self.request.url = 'https://example.com'
        self.response.headers = Mock(side_effect=Exception("Test exception"))
        
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 319)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 15)

if __name__ == '__main__':
    unittest.main()