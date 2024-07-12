import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk

class BasePassiveScanRuleTest(unittest.TestCase):
    def setUp(self):
        self.request = Mock(spec=Request)
        self.response = Mock(spec=Response)
        
        # Set up default attributes for request and response
        self.request.method = 'GET'
        self.request.url = 'http://example.com'
        self.request.headers = {}
        
        self.response.status_code = 200
        self.response.headers = {'Content-Type': 'text/html'}
        self.response.text = ''
    
    def tearDown(self):
        pass
    
    def set_response_content(self, content, content_type='text/html'):
        self.response.text = content
        self.response.headers['Content-Type'] = content_type
    
    def assert_alert(self, result, risk_category: Risk, confidence: Confidence):
        self.assertIsInstance(result, Alert)
        self.assertEqual(result.risk_category, risk_category)
        self.assertEqual(result.confidence, confidence)
    
    def assert_no_alert(self, result):
        self.assertIsInstance(result, NoAlert)

    def assert_scan_error(self, result):
        self.assertIsInstance(result, ScanError)