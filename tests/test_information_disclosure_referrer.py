import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.information_disclosure_referrer_scan_rule import InformationDisclosureReferrerScanRule

class TestInformationDisclosureReferrerScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = InformationDisclosureReferrerScanRule()

    def test_no_referrer_header(self):
        self.request.headers = {}
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_same_domain_referrer(self):
        self.request.url = 'https://example.com'
        self.request.headers = {'Referer': 'https://example.com/page'}
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_different_domain_no_sensitive_info(self):
        self.request.url = 'https://example.com'
        self.request.headers = {'Referer': 'https://otherdomain.com/page'}
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_sensitive_word_in_referrer(self):
        self.request.url = 'https://example.com'
        self.request.headers = {'Referer': 'https://otherdomain.com/page?password=secret'}
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)

    def test_email_in_referrer(self):
        self.request.url = 'https://example.com'
        self.request.headers = {'Referer': 'https://otherdomain.com/page?email=user@example.com'}
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)

    def test_credit_card_in_referrer(self):
        self.request.url = 'https://example.com'
        self.request.headers = {'Referer': 'https://otherdomain.com/page?cc=4111111111111111'}
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)

    def test_ssn_in_referrer(self):
        self.request.url = 'https://example.com'
        self.request.headers = {'Referer': 'https://otherdomain.com/page?ssn=123-45-6789'}
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)

    def test_multiple_referrer_headers(self):
        self.request.url = 'https://example.com'
        self.request.headers = {
            'Referer': [
                'https://otherdomain1.com/page',
                'https://otherdomain2.com/page?password=secret'
            ]
        }
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)

    def test_exception_handling(self):
        self.request.url = 'https://example.com'
        self.request.headers = Mock(side_effect=Exception("Test exception"))
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 200)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 13)

if __name__ == '__main__':
    unittest.main()