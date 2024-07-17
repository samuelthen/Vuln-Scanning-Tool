import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.directory_browsing_scan_rule import DirectoryBrowsingScanRule
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest

class TestDirectoryBrowsingScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = DirectoryBrowsingScanRule()

    def test_check_risk_apache_directory_listing(self):
        self.set_response_content('<title>Index of /some_directory/</title>\nSome Content')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_MEDIUM)

    def test_check_risk_iis_directory_listing(self):
        self.set_response_content('<pre><A HREF="/some_directory/">[To Parent Directory]</A><br><br>Some Content')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_MEDIUM)

    def test_check_risk_no_directory_listing(self):
        self.set_response_content('<html><body>No directory listing here</body></html>')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_non_html_response(self):
        self.set_response_content('Some binary data', content_type='application/octet-stream')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_exception(self):
        self.response.headers = Mock(side_effect=Exception("Test exception"))

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 548)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 16)

if __name__ == '__main__':
    unittest.main()
