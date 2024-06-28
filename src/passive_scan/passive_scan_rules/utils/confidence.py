from enum import Enum


class Confidence(Enum):
    CONFIDENCE_FALSE_POSITIVE = (0, 'False Positive')
    CONFIDENCE_LOW = (1, 'Low')
    CONFIDENCE_MEDIUM = (2, 'Medium')
    CONFIDENCE_HIGH = (3, 'High')
    CONFIDENCE_USER_CONFIRMED = (4, 'Confirmed')

    def __init__(self, code: int, confidence: str):
        self._code = code
        self._confidence = confidence

    def __len__(self):
        return 5

    @property
    def code(self):
        return self._code

    @property
    def confidence(self):
        return self._confidence
