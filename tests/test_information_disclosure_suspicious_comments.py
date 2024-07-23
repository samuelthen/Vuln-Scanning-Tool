import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.information_disclosure_suspicious_comments_scan_rule import InformationDisclosureSuspiciousCommentsScanRule

class TestInformationDisclosureSuspiciousCommentsScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = InformationDisclosureSuspiciousCommentsScanRule()

    def test_check_risk_no_suspicious_comments(self):
        self.set_response_content("This is a normal response with no suspicious comments.")
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_single_suspicious_comment(self):
        self.set_response_content("This response contains a TODO comment.")
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)
        self.assertIn("TODO", result.evidence)

    def test_check_risk_multiple_suspicious_comments(self):
        self.set_response_content("This response has a TODO and a FIXME comment.")
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)
        self.assertIn("TODO", result.evidence)
        self.assertIn("FIXME", result.evidence)

    def test_check_risk_case_insensitive(self):
        self.set_response_content("This response has a todo comment in lowercase.")
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_INFO, Confidence.CONFIDENCE_MEDIUM)
        self.assertIn("todo", result.evidence)

    def test_check_risk_empty_response(self):
        self.set_response_content("")
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_exception(self):
        self.response.text = Mock(side_effect=Exception("Test exception"))
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_scan_for_suspicious_comments(self):
        response_body = "TODO: Fix this later. FIXME: This is broken."
        result = self.scan_rule.scan_for_suspicious_comments(response_body)
        self.assertIn(r"\bTODO\b", result)
        self.assertIn(r"\bFIXME\b", result)
        self.assertEqual(result[r"\bTODO\b"], ["TODO"])
        self.assertEqual(result[r"\bFIXME\b"], ["FIXME"])

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 200)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 13)

if __name__ == '__main__':
    unittest.main()