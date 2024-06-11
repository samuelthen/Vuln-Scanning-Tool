from requests.models import Request, Response
from abc import ABC, abstractmethod
from .alert import Alert

class BasePassiveScanRule(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def check_risk(self, request: Request, response: Response) -> Alert:
        raise NotImplementedError("Subclass must implement abstract method")
    
