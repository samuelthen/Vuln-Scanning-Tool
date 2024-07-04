class PiiUtils:
    
    @staticmethod
    def is_valid_luhn(in_str: str) -> bool:
        sum = 0
        parity = len(in_str) % 2
        for index in range(len(in_str)):
            digit = int(in_str[index])
            if (index % 2) == parity:
                digit *= 2
                if digit > 9:
                    digit -= 9
            sum += digit
        return (sum % 10) == 0