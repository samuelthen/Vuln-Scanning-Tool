import unittest
from unittest.mock import Mock, patch
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.cross_domain_script_inclusion_scan_rule import CrossDomainScriptInclusionScanRule

class TestCrossDomainScriptInclusionScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = CrossDomainScriptInclusionScanRule()
        self.request.url = 'http://example.com'

    def test_no_script_tags(self):
        self.set_response_content('<html><body>No scripts here</body></html>')
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_same_domain_script(self):
        self.set_response_content('<html><script src="http://example.com/script.js"></script></html>')
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_cross_domain_script_with_integrity(self):
        self.set_response_content('<html><script src="https://otherdomain.com/script.js" integrity="sha256-abc123"></script></html>')
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_cross_domain_script_without_integrity(self):
        self.set_response_content('<html><script src="https://otherdomain.com/script.js"></script></html>')
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)

    def test_multiple_scripts_mixed(self):
        content = '''
        <html>
            <script src="http://example.com/safe.js"></script>
            <script src="https://otherdomain.com/unsafe.js"></script>
            <script src="https://anotherdomain.com/safe.js" integrity="sha256-def456"></script>
        </html>
        '''
        self.set_response_content(content)
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)
        self.assertIn('otherdomain.com/unsafe.js', result.evidence[0])

    def test_non_html_content(self):
        self.set_response_content('{"key": "value"}', content_type='application/json')
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_relative_url_script(self):
        self.set_response_content('<html><script src="/relative/path/script.js"></script></html>')
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    @patch('src.passive_scan.passive_scan_rules.cross_domain_script_inclusion_scan_rule.BeautifulSoup')
    def test_beautiful_soup_exception(self, mock_bs):
        mock_bs.side_effect = Exception("BeautifulSoup error")
        self.set_response_content('<html><script src="https://otherdomain.com/script.js"></script></html>')
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_empty_integrity_attribute(self):
        self.set_response_content('<html><script src="https://otherdomain.com/script.js" integrity=""></script></html>')
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)

    def test_malformed_url(self):
        self.set_response_content('<html><script src="http:malformed-url"></script></html>')
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 829)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 15)

if __name__ == '__main__':
    unittest.main()