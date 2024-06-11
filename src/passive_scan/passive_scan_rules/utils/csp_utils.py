from bs4 import BeautifulSoup

class CspUtils:
    def __init__(self):
        pass

    @staticmethod
    def has_meta_csp(html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        for meta_tag in soup.find_all('meta'):
            http_equiv = meta_tag.get('http-equiv')
            if http_equiv and http_equiv.lower() == 'content-security-policy':
                return True
        return False