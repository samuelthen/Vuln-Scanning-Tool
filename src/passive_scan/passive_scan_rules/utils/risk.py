from enum import Enum


class Risk(Enum):
    RISK_INFO = (0, 'Informational')
    RISK_LOW = (1, 'Low')
    RISK_MEDIUM = (2, 'Medium')
    RISK_HIGH = (3, 'High')

    NO_RISK = (-1, 'No Alert')
    ERROR = (-2, 'Error')

    def __init__(self, code: int, risk: str):
        self._code = code
        self._risk = risk

    def __len__(self):
        return 4

    @property
    def code(self):
        return self._code

    @property
    def risk(self):
        return self._risk
