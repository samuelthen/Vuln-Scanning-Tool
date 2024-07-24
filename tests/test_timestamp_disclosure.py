import unittest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta
from requests.models import Request, Response
from src.passive_scan.passive_scan_rules.timestamp_disclosure_scan_rule import TimestampDisclosureScanRule
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest

class TestTimestampDisclosureScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = TimestampDisclosureScanRule()
        self.current_time = datetime.now()

    def test_check_risk_no_timestamp(self):
        self.response.text = "No timestamp here"
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_valid_timestamp_in_body(self):
        timestamp = int(self.current_time.timestamp())
        self.response.text = f"Some text with a timestamp: {timestamp}"
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_LOW)
        self.assertIn(str(timestamp), result.evidence)

    def test_check_risk_valid_timestamp_in_header(self):
        timestamp = int(self.current_time.timestamp())
        self.response.headers['Custom-Header'] = str(timestamp)
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_LOW)
        self.assertIn(str(timestamp), result.evidence)

    def test_check_risk_ignored_headers(self):
        timestamp = int(self.current_time.timestamp())
        self.response.headers['Age'] = str(timestamp)
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_timestamp_out_of_range(self):
        future_timestamp = int((self.current_time + timedelta(days=365 * 11)).timestamp())
        self.response.text = f"Future timestamp: {future_timestamp}"
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_invalid_timestamp(self):
        self.response.text = "Invalid timestamp: 99999999999999999"
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    @patch('logging.Logger.error')
    def test_check_risk_exception(self, mock_error):
        self.response.headers = Mock(side_effect=Exception("Test exception"))
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)
        mock_error.assert_called_once()

    def test_build_alert(self):
        timestamp = self.current_time
        evidence = str(int(timestamp.timestamp()))
        alert = self.scan_rule.build_alert("Unix", evidence, "", timestamp)
        self.assertEqual(alert.risk_category, Risk.RISK_LOW)
        self.assertEqual(alert.confidence, Confidence.CONFIDENCE_LOW)
        self.assertIn("Timestamp disclosure detected - Unix", alert.description)
        self.assertIn(evidence, alert.evidence)
        self.assertIn(timestamp.strftime("%Y-%m-%d %H:%M:%S"), alert.evidence)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 200)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 13)

if __name__ == '__main__':
    unittest.main()