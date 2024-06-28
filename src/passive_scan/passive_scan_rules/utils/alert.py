from risk import Risk
from confidence import Confidence

class Alert:
    """
    A class to represent an alert for a vulnerability scan.

    Attributes:
        VALID_RISK_CATEGORIES (set): A set of valid risk categories.
        risk_category (str): The risk category of the alert.
        msg_ref (str, optional): A reference to the message related to the alert.
        description (str, optional): A description of the alert.
        evidence (str, optional): Evidence supporting the alert.
        cwe_id (int, optional): The CWE ID associated with the alert.
        wasc_id (int, optional): The WASC ID associated with the alert.

    Note:
        Additional attributes can be added as needed.
    """
    # VALID_RISK_CATEGORIES = {"high", "medium", "low", "informational", "no alert", "error"}

    def __init__(self, risk_category: Risk, msg_ref=None, description=None, 
                 evidence=None, cwe_id=None, wasc_id=None, confidence: Confidence=None,
                 attack=None, param=None, method=None):
        """
        Constructs all the necessary attributes for the Alert object.

        Args:
            risk_category (str): The risk category of the alert.
            msg_ref (str, optional): A reference to the message related to the alert. Defaults to None.
            description (str, optional): A description of the alert. Defaults to None.
            evidence (str, optional): Evidence supporting the alert. Defaults to None.
            cwe_id (int, optional): The CWE ID associated with the alert. Defaults to None.
            wasc_id (int, optional): The WASC ID associated with the alert. Defaults to None.

        Raises:
            ValueError: If the risk_category is not in the VALID_RISK_CATEGORIES set.
        """
        # if risk_category.lower() not in self.VALID_RISK_CATEGORIES:
        #     raise ValueError(f"Invalid risk category '{risk_category}'. Valid options are: {self.VALID_RISK_CATEGORIES}")
        
        self.risk_category = risk_category
        self.msg_ref =  msg_ref
        self.description = description
        self.evidence = evidence
        self.cwe_id = cwe_id
        self.wasc_id = wasc_id
        self.attack = attack
        self.param = param
        self.method = method
        self.confidence = confidence

    def get(self):
        """
        Returns a dictionary representation of the Alert object with non-None values.

        Returns:
            dict: A dictionary of the Alert object's attributes.
        """
        return {key: value for key, value in vars(self).items() if value is not None}
    
    def __str__(self) -> str:
        """
        Returns a string representation of the Alert object.

        Returns:
            str: A string representation of the Alert object.
        """
        return str(self.get())

class NoAlert(Alert):
    """
    A class to represent an alert indicating no issues found.

    Inherits from the Alert class.
    """
    def __init__(self, description=None, msg_ref=None):
        """
        Constructs all the necessary attributes for the NoAlert object.

        Args:
            description (str, optional): A description of the alert. Defaults to None.
        """
        super().__init__(risk_category=Risk.NO_RISK, description=description, msg_ref=msg_ref)

class ScanError(Alert):
    """
    A class to represent an alert indicating an error during scanning.

    Inherits from the Alert class.
    """
    def __init__(self, description=None, msg_ref=None):
        """
        Constructs all the necessary attributes for the ScanError object.

        Args:
            description (str, optional): A description of the alert. Defaults to None.
        """
        super().__init__(risk_category=Risk.ERROR, description=description, msg_ref=msg_ref)
