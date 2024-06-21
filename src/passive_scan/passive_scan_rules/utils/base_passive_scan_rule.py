from requests.models import Request, Response
from abc import ABC, abstractmethod
from .alert import Alert

class BasePassiveScanRule(ABC):
    """
    An abstract base class for passive scan rules.

    Methods:
        check_risk(request: Request, response: Response) -> Alert:
            Checks for risk in the given request and response.
        
        get_cwe_id() -> int:
            Returns the CWE ID for the scan rule.
        
        get_wasc_id() -> int:
            Returns the WASC ID for the scan rule.
    """
    def __init__(self):
        """
        Constructs the BasePassiveScanRule object.
        """
        pass

    @abstractmethod
    def check_risk(self, request: Request, response: Response) -> Alert:
        """
        Abstract method to check for risk in the given request and response.

        Args:
            request (Request): The HTTP request object.
            response (Response): The HTTP response object.

        Returns:
            Alert: An Alert object indicating the result of the risk check.
        """
        raise NotImplementedError("Subclass must implement abstract method")
    
    @abstractmethod
    def get_cwe_id(self):
        """
        Abstract method to get the CWE ID for the scan rule.

        Returns:
            int: The CWE ID.
        """
        return 0

    @abstractmethod
    def get_wasc_id(self):
        """
        Abstract method to get the WASC ID for the scan rule.

        Returns:
            int: The WASC ID.
        """
        return 0
