class Alert:
    VALID_RISK_CATEGORIES = {"high", "medium", "low", "informational", "no alert", "error"}

    def __init__(self, risk_category: str, msg_ref=None, description=None, evidence=None, cwe_id=None, wasc_id=None):
        if risk_category.lower() not in self.VALID_RISK_CATEGORIES:
            raise ValueError(f"Invalid risk category '{risk_category}'. Valid options are: {self.VALID_RISK_CATEGORIES}")
        
        self.risk_category = risk_category
        self.msg_ref =  msg_ref
        self.description = description
        self.evidence = evidence
        self.cwe_id = cwe_id
        self.wasc_id = wasc_id

    def get(self):
        return {key: value for key, value in vars(self).items() if value is not None}
    
    def __str__(self) -> str:
        return str(self.get())
    
class NoAlert(Alert):
    def __init__(self, description=None):
        super().__init__(risk_category="No Alert", description=description)

class ScanError(Alert):
    def __init__(self, description=None):
        super().__init__(risk_category="Error", description=description)