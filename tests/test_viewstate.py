import unittest
from unittest.mock import Mock, patch
from requests.models import Request, Response
from bs4 import BeautifulSoup
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.viewstate_scan_rule import ViewstateScanRule, Viewstate, ViewstateVersion

import unittest
from unittest.mock import Mock, patch
from requests.models import Request, Response
from src.passive_scan.passive_scan_rules.viewstate_scan_rule import ViewstateScanRule
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk

class TestViewstateScanRule(unittest.TestCase):
    def setUp(self):
        self.scan_rule = ViewstateScanRule()
        self.request = Mock(spec=Request)
        self.response = Mock(spec=Response)
        self.response.text = ""

    def test_no_hidden_fields(self):
        with patch.object(self.scan_rule, 'get_hidden_fields', return_value={}):
            result = self.scan_rule.check_risk(self.request, self.response)
            self.assertIsInstance(result, NoAlert)

    def test_invalid_viewstate(self):
        with patch.object(self.scan_rule, 'get_hidden_fields', return_value={'__VIEWSTATE': 'invalid'}):
            result = self.scan_rule.check_risk(self.request, self.response)
            self.assertIsInstance(result, NoAlert)

    def test_no_mac_for_sure(self):
        mock_viewstate = Mock(is_valid=True, has_mac_test1=lambda: False, has_mac_test2=lambda: False)
        with patch.object(self.scan_rule, 'get_hidden_fields', return_value={'__VIEWSTATE': 'valid'}):
            with patch.object(self.scan_rule, 'extract_viewstate', return_value=mock_viewstate):
                result = self.scan_rule.check_risk(self.request, self.response)
                self.assertIsInstance(result, Alert)
                self.assertEqual(result.risk_category, Risk.RISK_HIGH)
                self.assertEqual(result.confidence, Confidence.CONFIDENCE_MEDIUM)
                self.assertEqual(result.msg_ref, "pscanrules.viewstate.nomac.sure")

    def test_no_mac_unsure(self):
        mock_viewstate = Mock(is_valid=True, has_mac_test1=lambda: False, has_mac_test2=lambda: True)
        with patch.object(self.scan_rule, 'get_hidden_fields', return_value={'__VIEWSTATE': 'valid'}):
            with patch.object(self.scan_rule, 'extract_viewstate', return_value=mock_viewstate):
                result = self.scan_rule.check_risk(self.request, self.response)
                self.assertIsInstance(result, Alert)
                self.assertEqual(result.risk_category, Risk.RISK_HIGH)
                self.assertEqual(result.confidence, Confidence.CONFIDENCE_LOW)
                self.assertEqual(result.msg_ref, "pscanrules.viewstate.nomac.unsure")

    def test_old_asp_version(self):
        mock_viewstate = Mock(
            is_valid=True, 
            has_mac_test1=lambda: True, 
            has_mac_test2=lambda: True, 
            is_latest_asp_net_version=False,  # Changed from is_latest_asp_net_version
            version=Mock()  # Add this to avoid attribute errors
        )
        with patch.object(self.scan_rule, 'get_hidden_fields', return_value={'__VIEWSTATE': 'valid'}):
            with patch.object(self.scan_rule, 'extract_viewstate', return_value=mock_viewstate):
                result = self.scan_rule.check_risk(self.request, self.response)
                self.assertIsInstance(result, Alert)
                self.assertEqual(result.risk_category, Risk.RISK_LOW)
                self.assertEqual(result.confidence, Confidence.CONFIDENCE_MEDIUM)
                self.assertEqual(result.msg_ref, "pscanrules.viewstate.oldver")

    def test_viewstate_analyzer_result(self):
        mock_viewstate = Mock(is_valid=True, has_mac_test1=lambda: True, has_mac_test2=lambda: True, is_latest_aspnet_version=True, decoded_value=b"test@example.com")
        mock_result = Mock(has_results=lambda: True, get_result_extract=lambda: {"test@example.com"})
        with patch.object(self.scan_rule, 'get_hidden_fields', return_value={'__VIEWSTATE': 'valid'}):
            with patch.object(self.scan_rule, 'extract_viewstate', return_value=mock_viewstate):
                with patch('src.passive_scan.passive_scan_rules.viewstate_scan_rule.ViewstateAnalyzer.get_search_results', return_value=[mock_result]):
                    result = self.scan_rule.check_risk(self.request, self.response)
                    self.assertIsInstance(result, Alert)
                    self.assertEqual(result.risk_category, Risk.RISK_MEDIUM)
                    self.assertEqual(result.confidence, Confidence.CONFIDENCE_MEDIUM)
                    self.assertIn("test@example.com", result.evidence)

    def test_split_viewstate(self):
        mock_viewstate = Mock(is_valid=True, has_mac_test1=lambda: True, has_mac_test2=lambda: True, is_latest_aspnet_version=True, is_split=True)
        with patch.object(self.scan_rule, 'get_hidden_fields', return_value={'__VIEWSTATE': 'valid', '__VIEWSTATEFIELDCOUNT': '2'}):
            with patch.object(self.scan_rule, 'extract_viewstate', return_value=mock_viewstate):
                with patch('src.passive_scan.passive_scan_rules.viewstate_scan_rule.ViewstateAnalyzer.get_search_results', return_value=[]):
                    result = self.scan_rule.check_risk(self.request, self.response)
                    self.assertIsInstance(result, Alert)
                    self.assertEqual(result.risk_category, Risk.RISK_INFO)
                    self.assertEqual(result.confidence, Confidence.CONFIDENCE_LOW)
                    self.assertEqual(result.msg_ref, "pscanrules.viewstate.split")

    def test_no_issues(self):
        mock_viewstate = Mock(is_valid=True, has_mac_test1=lambda: True, has_mac_test2=lambda: True, is_latest_aspnet_version=True, is_split=False)
        with patch.object(self.scan_rule, 'get_hidden_fields', return_value={'__VIEWSTATE': 'valid'}):
            with patch.object(self.scan_rule, 'extract_viewstate', return_value=mock_viewstate):
                with patch('src.passive_scan.passive_scan_rules.viewstate_scan_rule.ViewstateAnalyzer.get_search_results', return_value=[]):
                    result = self.scan_rule.check_risk(self.request, self.response)
                    self.assertIsInstance(result, NoAlert)

    def test_exception_handling(self):
        with patch.object(self.scan_rule, 'get_hidden_fields', side_effect=Exception("Test exception")):
            result = self.scan_rule.check_risk(self.request, self.response)
            self.assertIsInstance(result, ScanError)
            self.assertEqual(result.description, "Test exception")

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 642)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 14)

if __name__ == '__main__':
    unittest.main()