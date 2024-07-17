import unittest
from unittest.mock import Mock, patch
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.csrf_countermeasures_scan_rule import CsrfCountermeasuresScanRule

class TestCsrfCountermeasuresScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = CsrfCountermeasuresScanRule()

    def test_check_risk_with_csrf_token(self):
        self.response.text = '''
        <html>
        <body>
            <form id="test_form">
                <input type="hidden" name="csrf_token" value="token_value">
            </form>
        </body>
        </html>
        '''
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_without_csrf_token(self):
        self.response.text = '''
        <html>
        <body>
            <form id="test_form">
                <input type="text" name="username">
                <input type="password" name="password">
            </form>
        </body>
        </html>
        '''
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_LOW)

    def test_check_risk_empty_form(self):
        self.response.text = '''
        <html>
        <body>
            <form id="empty_form"></form>
        </body>
        </html>
        '''
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_MEDIUM, Confidence.CONFIDENCE_LOW)

    def test_check_risk_no_forms(self):
        self.response.text = '''
        <html>
        <body>
            <p>No forms here!</p>
        </body>
        </html>
        '''
        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_check_risk_ignore_form(self):
        self.response.text = '''
        <html>
        <body>
            <form id="ignored_form">
                <input type="text" name="ignored_input">
            </form>
        </body>
        </html>
        '''
        with patch.object(self.scan_rule, 'get_csrf_ignore_list', return_value=['ignored_form']):
            result = self.scan_rule.check_risk(self.request, self.response)
            self.assert_no_alert(result)

    def test_check_risk_ignore_form_by_attribute(self):
        self.response.text = '''
        <html>
        <body>
            <form id="form_with_ignore_attribute" ignore="true">
                <input type="text" name="ignored_input">
            </form>
        </body>
        </html>
        '''
        with patch.object(self.scan_rule, 'get_csrf_ignore_att_name', return_value='ignore'), \
             patch.object(self.scan_rule, 'get_csrf_ignore_att_value', return_value='true'):
            result = self.scan_rule.check_risk(self.request, self.response)
            self.assert_no_alert(result)

    def test_check_risk_exception_handling(self):
        self.response.text = '''
        <html>
        <body>
            <form id="test_form">
                <input type="text" name="username">
                <input type="password" name="password">
            </form>
        </body>
        </html>
        '''
        with patch('bs4.BeautifulSoup', side_effect=Exception("Test exception")):
            result = self.scan_rule.check_risk(self.request, self.response)
            self.assert_scan_error(result)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 352)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 9)

if __name__ == '__main__':
    unittest.main()
