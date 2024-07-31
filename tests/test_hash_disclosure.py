import unittest
from unittest.mock import Mock
from requests.models import Request, Response
from src.passive_scan.passive_scan_rules.hash_disclosure_scan_rule import HashDisclosureScanRule
from tests.test_utils.base_passive_scan_rule_test import BasePassiveScanRuleTest
from src.passive_scan.passive_scan_rules.utils.alert import Alert, NoAlert, ScanError
from src.passive_scan.passive_scan_rules.utils.confidence import Confidence
from src.passive_scan.passive_scan_rules.utils.risk import Risk

class TestHashDisclosureScanRule(BasePassiveScanRuleTest):
    def setUp(self):
        super().setUp()
        self.scan_rule = HashDisclosureScanRule()
        self.request.data = ''  # Ensure the 'data' attribute is set

    def test_no_hash_in_request_or_response(self):
        self.request.data = 'No hash data here'
        self.response.text = 'No hash data here either'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_no_alert(result)

    def test_hash_in_request_headers(self):
        self.request.headers = {'Authorization': '$NT$7f8fe03093cc84b267b109625f6bbf4b'} # NTLM
        self.request.data = ''  # Ensure the 'data' attribute is set

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_HIGH, Confidence.CONFIDENCE_HIGH)

    def test_hash_in_response_body(self):
        self.request.data = ''  # Ensure the 'data' attribute is set
        self.response.text = 'Some sensitive hash 0E6A48F765D0FFFFF6247FA80D748E615F91DD0C7431E4D9 found' # Mac OSX salted SHA-1

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_HIGH, Confidence.CONFIDENCE_MEDIUM)

    def test_multiple_hashes_in_response(self):
        self.request.data = ''  # Ensure the 'data' attribute is set
        self.response.text = 'Hashes: $6$zWwwXKNj$gLAOoZCjcr8p/.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcVEJLT/rSwZcDMlVVf/bhf.1, \
                                    $5$rounds=5000$usesomesillystri$KqJWpanXZHKq2BOB43TSaYhEWsQ1Lr5QNyPCDH/Tp.6' # SHA-512 and SHA-256

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_HIGH, Confidence.CONFIDENCE_HIGH)

    def test_invalid_pattern_exception(self):
        self.request.data = ''  # Ensure the 'data' attribute is set
        mock_headers = Mock()
        mock_headers.__str__ = Mock(side_effect=Exception("Invalid pattern"))
        
        self.response.headers = mock_headers

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_scan_error(result)

    def test_hash_in_request_data(self):
        self.request.data = '$1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/' #

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_HIGH, Confidence.CONFIDENCE_HIGH)

    def test_sha256_hash(self):
        self.request.data = ''  # Ensure the 'data' attribute is set
        self.response.text = 'Here is a SHA-256 hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_LOW)

    def test_md5_hash(self):
        self.request.data = ''  # Ensure the 'data' attribute is set
        self.response.text = 'Here is a MD5 hash: d41d8cd98f00b204e9800998ecf8427e'

        result = self.scan_rule.check_risk(self.request, self.response)
        self.assert_alert(result, Risk.RISK_LOW, Confidence.CONFIDENCE_LOW)

    def test_get_cwe_id(self):
        self.assertEqual(self.scan_rule.get_cwe_id(), 200)

    def test_get_wasc_id(self):
        self.assertEqual(self.scan_rule.get_wasc_id(), 13)

if __name__ == '__main__':
    unittest.main()
