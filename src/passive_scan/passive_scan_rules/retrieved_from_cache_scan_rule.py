import logging
from requests.models import Request, Response
from .utils.base_passive_scan_rule import BasePassiveScanRule
from .utils.alert import Alert, NoAlert, ScanError
from .utils.confidence import Confidence
from .utils.risk import Risk
from .utils.common_alert_tag import CommonAlertTag

logger = logging.getLogger(__name__)

class RetrievedFromCacheScanRule(BasePassiveScanRule):
    """
    Passive scan rule to detect if content has been served from a shared cache.
    """
    MSG_REF = "pscanrules.retrievedfromcache"
    RISK = Risk.RISK_INFO
    CONFIDENCE = Confidence.CONFIDENCE_MEDIUM

    ALERT_TAGS = [
        CommonAlertTag.WSTG_V42_ATHN_06_CACHE_WEAKNESS
    ]

    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Check if the response was served from a shared cache.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        try:
            logger.debug("Checking URL %s to see if it was served from a shared cache", request.url)

            # Process the "X-Cache" headers
            xcache_headers = response.headers.get('X-Cache', [])
            if not isinstance(xcache_headers, list):
                xcache_headers = [xcache_headers]
            
            for xcache_header in xcache_headers:
                for proxy_server_details in xcache_header.split(","):
                    proxy_server_details = proxy_server_details.strip()
                    logger.debug("Proxy HIT/MISS details [%s]", proxy_server_details)
                    details_array = proxy_server_details.split(" ", 2)
                    if len(details_array) >= 1:
                        hit_or_miss = details_array[0].upper()
                        if hit_or_miss == "HIT":
                            evidence = proxy_server_details
                            logger.debug("%s was served from a cache, due to presence of a 'HIT' in the 'X-Cache' response header", request.url)
                            return Alert(risk_category=self.RISK,
                                         confidence=self.CONFIDENCE,
                                         description="Content served from a shared cache",
                                         msg_ref=self.MSG_REF,
                                         evidence=evidence,
                                         cwe_id=self.get_cwe_id(),
                                         wasc_id=self.get_wasc_id())
            
            # Process the "Age" headers
            age_headers = response.headers.get('Age', [])
            if not isinstance(age_headers, list):
                age_headers = [age_headers]
            
            for age_header in age_headers:
                logger.debug("Validating Age header value [%s]", age_header)
                try:
                    age_as_long = int(age_header)
                    if age_as_long >= 0:
                        evidence = f"Age: {age_header}"
                        logger.debug("%s was served from a HTTP/1.1 cache, due to presence of a valid (non-negative integer) 'Age' response header value", request.url)
                        return Alert(risk_category=self.RISK,
                                     confidence=self.CONFIDENCE,
                                     description="Content served from a HTTP/1.1 cache",
                                     msg_ref=self.MSG_REF,
                                     evidence=evidence,
                                     cwe_id=self.get_cwe_id(),
                                     wasc_id=self.get_wasc_id())
                except ValueError:
                    pass

            return NoAlert(msg_ref=self.MSG_REF)
        
        except Exception as e:
            logger.error("An error occurred while checking if a URL was served from a cache", e)
            return ScanError(description=str(e), msg_ref=self.MSG_REF)
    
    def __str__(self) -> str:
        """
        Returns a string representation of the RetrievedFromCacheScanRule object.

        Returns:
            str: A string representation of the RetrievedFromCacheScanRule object.
        """
        return "Retrieved From Cache Scan Rule"

    def get_cwe_id(self):
        """
        Get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 524  # CWE-524: Information Exposure Through Cache

    def get_wasc_id(self):
        """
        Get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 13  # WASC-13: Info Leakage
