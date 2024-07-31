import unittest
from unittest.mock import Mock, patch
from requests.models import Request, Response
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.insecure_jsf_view_state_passive_scan_rule import InsecureJsfViewStatePassiveScanRule
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest

class TestInsecureJsfViewStatePassiveScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = InsecureJsfViewStatePassiveScanRule()

    def test_check_risk_insecure_viewstate(self):
        self.set_response_content('<input id="javax.faces.ViewState" value="insecure_viewstate_value" />', content_type='text/html')
        
        with patch.object(self.scan_rule, 'is_view_state_secure', return_value=False):
            result = self.scan_rule.check_risk(self.request, self.response)
            self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_LOW)

    def test_check_risk_secure_viewstate(self):
        self.set_response_content('<input id="javax.faces.ViewState" value="secure_viewstate_value" />', content_type='text/html')
        
        with patch.object(self.scan_rule, 'is_view_state_secure', return_value=True):
            result = self.scan_rule.check_risk(self.request, self.response)
            self.assert_no_alert(result)

    def test_check_risk_no_viewstate(self):
        self.set_response_content('<html><body>No ViewState here</body></html>', content_type='text/html')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_non_html_response(self):
        self.set_response_content('Some binary data', content_type='application/octet-stream')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_exception(self):
        self.response.headers = Mock()
        self.response.headers.get = Mock(side_effect=Exception("Test exception"))

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_is_view_state_secure_base64_encoded(self):
        view_state = "SGVsbG8gV29ybGQ="  # Base64 encoded "Hello World"
        with patch.object(self.scan_rule, 'is_raw_view_state_secure', return_value=True):
            self.assertTrue(self.scan_rule.is_view_state_secure(view_state))

    def test_is_view_state_secure_compressed(self):
        view_state = "H4sIAAAAAAAAA0vOzy0oSi0uTk0BAIoTRoUNAAAA"  # Compressed and Base64 encoded "Hello World"
        with patch.object(self.scan_rule, 'is_raw_view_state_secure', return_value=True):
            self.assertTrue(self.scan_rule.is_view_state_secure(view_state))

    def test_is_view_state_secure_raw(self):
        view_state = "Hello World"
        with patch.object(self.scan_rule, 'is_raw_view_state_secure', return_value=True):
            self.assertTrue(self.scan_rule.is_view_state_secure(view_state))

    def test_is_raw_view_state_secure(self):
        self.assertTrue(self.scan_rule.is_raw_view_state_secure("SecureViewState"))
        self.assertFalse(self.scan_rule.is_raw_view_state_secure("InsecureJavaViewState"))

    def test_is_view_state_stored_on_server(self):
        self.assertTrue(self.scan_rule.is_view_state_stored_on_server("server:12345"))
        self.assertFalse(self.scan_rule.is_view_state_stored_on_server("clientside12345"))

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 642)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 14)

if __name__ == '__main__':
    unittest.main()