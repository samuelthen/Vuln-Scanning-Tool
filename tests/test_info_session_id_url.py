import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.info_session_id_url_scan_rule import InfoSessionIdUrlScanRule

class TestInfoSessionIdUrlScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = InfoSessionIdUrlScanRule()

    def test_check_risk_session_id_in_url_param(self):
        self.request.url = 'https://example.com?jsessionid=ABCDEF123456'
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_HIGH)

    def test_check_risk_session_id_in_url_path(self):
        self.request.url = 'https://example.com/path/to/resource;jsessionid=ABCDEF123456'
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_HIGH)

    def test_check_risk_no_session_id(self):
        self.request.url = 'https://example.com/path/to/resource'
        self.response.content = b'Some content'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_external_link_exposure(self):
        self.request.url = 'https://example.com?jsessionid=ABCDEF123456'
        self.response.url = 'https://example.com'
        self.response.text = '<a href="https://malicious.com">Click here</a>'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_HIGH)

    def test_check_risk_no_external_link_exposure(self):
        self.request.url = 'https://example.com?jsessionid=ABCDEF123456'
        self.response.url = 'https://example.com'
        self.response.text = '<a href="https://example.com/anotherpage">Click here</a>'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_HIGH)

    def test_check_risk_exception(self):
        self.request.url = Mock(side_effect=Exception("Test exception"))

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)
        
    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 200)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 13)

if __name__ == '__main__':
    unittest.main()
