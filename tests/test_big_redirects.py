import unittest
from unittest.mock import Mock, patch, PropertyMock
from requests.models import Request, Response
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk
from src.passive_scan.passive_scan_rules.big_redirects_scan_rule import BigRedirectsScanRule

class TestBigRedirectsScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.rule = BigRedirectsScanRule()
    
    def test_redirect_without_location_header(self):
        self.response.status_code = 302
        self.response.headers.pop('Location', None)
        
        result = self.rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)
    
    def test_redirect_with_small_response_body(self):
        self.response.status_code = 301
        self.response.headers['Location'] = 'http://example.com/redirect'
        self.set_response_content('Short response body')
        
        result = self.rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)
    
    def test_redirect_with_large_response_body(self):
        self.response.status_code = 302
        self.response.headers['Location'] = 'http://example.com/redirect'
        large_content = 'a' * 500
        self.set_response_content(large_content)
        
        result = self.rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)
    
    def test_redirect_with_multiple_hrefs(self):
        self.response.status_code = 302
        self.response.headers['Location'] = 'http://example.com/redirect'
        self.set_response_content('<a href="http://example1.com"></a><a href="http://example2.com"></a>')
        
        result = self.rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_MEDIUM)
    
    def test_non_redirect_response(self):
        self.response.status_code = 200
        self.set_response_content('This is a normal response.')
        
        result = self.rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_exception_handling(self):
        def raise_exception(*args, **kwargs):
            raise Exception('Test exception')

        # Ensure the response has a redirect status code
        self.response.status_code = 302
        self.response.headers['Location'] = 'http://example.com/redirect'

        with patch.object(BigRedirectsScanRule, 'get_predicted_response_size', side_effect=raise_exception):
            with patch.object(Response, 'text', new_callable=PropertyMock, return_value='dummy text'):
                result = self.rule.check_risk(self.request, self.response)
                self.assert_scan_error(result)

if __name__ == '__main__':
    unittest.main()
