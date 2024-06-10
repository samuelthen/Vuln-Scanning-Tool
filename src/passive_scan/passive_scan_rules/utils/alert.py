class Alert:
    def __init__(self, risk_category=None, description=None, evidence=None):
        self.risk_category = risk_category
        self.description = description
        self.evidence = evidence

    def get(self):
        return {key: value for key, value in vars(self).items()}