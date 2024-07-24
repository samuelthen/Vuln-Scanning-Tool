import unittest
from unittest.mock import Mock, patch
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.retrieved_from_cache_scan_rule import RetrievedFromCacheScanRule

class TestRetrievedFromCacheScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = RetrievedFromCacheScanRule()

    def test_check_risk_no_cache_headers(self):
        self.request.url = 'https://example.com'
        self.response.headers = {}

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_x_cache_hit(self):
        self.request.url = 'https://example.com'
        self.response.headers = {'X-Cache': 'HIT from cache-server'}

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)
        self.assertEqual(result.evidence, 'HIT from cache-server')

    def test_check_risk_x_cache_miss(self):
        self.request.url = 'https://example.com'
        self.response.headers = {'X-Cache': 'MISS from cache-server'}

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_x_cache_multiple(self):
        self.request.url = 'https://example.com'
        self.response.headers = {'X-Cache': ['MISS from server1', 'HIT from server2']}

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)
        self.assertEqual(result.evidence, 'HIT from server2')

    def test_check_risk_age_header_valid(self):
        self.request.url = 'https://example.com'
        self.response.headers = {'Age': '3600'}

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)
        self.assertEqual(result.evidence, 'Age: 3600')

    def test_check_risk_age_header_invalid(self):
        self.request.url = 'https://example.com'
        self.response.headers = {'Age': 'invalid'}

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_age_header_negative(self):
        self.request.url = 'https://example.com'
        self.response.headers = {'Age': '-1'}

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_exception(self):
        self.request.url = 'https://example.com'
        self.response.headers = {'X-Cache': 'HIT from cache-server'}
        
        # Simulate an exception
        self.response.headers = Mock(side_effect=Exception("Test exception"))

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 524)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 13)

if __name__ == '__main__':
    unittest.main()