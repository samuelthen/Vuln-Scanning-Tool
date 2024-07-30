import unittest
from unittest.mock import Mock, patch
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.link_target_scan_rule import LinkTargetScanRule

class TestLinkTargetScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = LinkTargetScanRule()

    def test_check_risk_no_vulnerable_links(self):
        self.request.url = 'https://example.com'
        self.set_response_content('''
            <html>
                <body>
                    <a href="https://example.com/page">Safe Link</a>
                    <a href="https://example.com/page" target="_blank" rel="noopener">Safe Blank Link</a>
                </body>
            </html>
        ''')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_vulnerable_link(self):
        self.request.url = 'https://example.com'
        self.set_response_content('''
            <html>
                <body>
                    <a href="https://other-domain.com" target="_blank">Vulnerable Link</a>
                </body>
            </html>
        ''')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_MEDIUM)

    def test_check_risk_non_html_response(self):
        self.request.url = 'https://example.com'
        self.set_response_content('{"key": "value"}', content_type='application/json')

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    @patch('src.passive_scan.passive_scan_rules.link_target_scan_rule.BeautifulSoup')
    def test_check_risk_exception(self, mock_bs):
        self.request.url = 'https://example.com'
        self.set_response_content('<html><body>Test</body></html>')
        mock_bs.side_effect = Exception("Test exception")

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_is_link_from_other_domain(self):
        host = 'example.com'
        context_list = ['example.com', 'sub.example.com']
        
        self.assertTrue(self.scan_rule.is_link_from_other_domain(host, 'https://other-domain.com', context_list))
        self.assertFalse(self.scan_rule.is_link_from_other_domain(host, 'https://example.com', context_list))
        self.assertFalse(self.scan_rule.is_link_from_other_domain(host, 'https://sub.example.com', context_list))
        self.assertFalse(self.scan_rule.is_link_from_other_domain(host, '/relative-path', context_list))

    def test_check_element(self):
        from bs4 import BeautifulSoup

        html = '''
            <a href="#" target="_blank">Vulnerable</a>
            <a href="#" target="_blank" rel="noopener">Safe</a>
            <a href="#" target="_self">Safe</a>
        '''
        soup = BeautifulSoup(html, 'html.parser')
        links = soup.find_all('a')

        self.assertTrue(self.scan_rule.check_element(links[0]))
        self.assertFalse(self.scan_rule.check_element(links[1]))
        self.assertFalse(self.scan_rule.check_element(links[2]))

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 1022)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 14)

if __name__ == '__main__':
    unittest.main()