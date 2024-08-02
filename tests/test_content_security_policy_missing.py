import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.utils.common_alert_tag import CommonAlertTag
from src.passive_scan.passive_scan_rules.content_security_policy_missing_scan_rule import ContentSecurityPolicyMissingScanRule

class TestContentSecurityPolicyMissingScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = ContentSecurityPolicyMissingScanRule()

    def test_missing_csp_header(self):
        self.response.headers = {
            'Content-Type': 'text/html'
        }
        self.response.text = '<html></html>'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_HIGH)

    def test_meta_csp_header_present(self):
        self.response.headers = {
            'Content-Type': 'text/html'
        }
        self.response.text = '<html><meta http-equiv="Content-Security-Policy" content="default-src \'self\'"></html>'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_obsolete_csp_header(self):
        self.response.headers = {
            'Content-Type': 'text/html',
            'X-Content-Security-Policy': 'default-src \'self\''
        }
        self.response.text = '<html><meta http-equiv="Content-Security-Policy" content="default-src \'self\'"></html>'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)

    def test_csp_report_only_header(self):
        self.response.headers = {
            'Content-Type': 'text/html',
            'Content-Security-Policy-Report-Only': 'default-src \'self\''
        }
        self.response.text = '<html><meta http-equiv="Content-Security-Policy" content="default-src \'self\'"></html>'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)

    def test_non_html_response(self):
        self.response.headers = {
            'Content-Type': 'application/json'
        }
        self.response.text = '{"key": "value"}'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_html_with_csp_header(self):
        self.response.headers = {
            'Content-Type': 'text/html',
            'Content-Security-Policy': 'default-src \'self\''
        }
        self.response.text = '<html></html>'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_exception(self):
        self.response.headers = {'Content-Type': 'text/html'}
        self.response.text = '<html></html>'
        
        # Simulate an exception
        self.response.headers = Mock(side_effect=Exception("Test exception"))

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 693)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 15)

if __name__ == '__main__':
    unittest.main()
