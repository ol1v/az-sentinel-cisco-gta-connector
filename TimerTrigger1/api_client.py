# api_client.py

import requests
from requests.auth import HTTPBasicAuth

def get_access_token(client_id, client_secret):
    TOKEN_URL = "https://visibility.eu.amp.cisco.com/iroh/oauth2/token"

    # headers
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    # body
    data = {
        "grant_type": "client_credentials",
    }

    # POST request with Basic Authentication
    response = requests.post(
        TOKEN_URL,
        headers=headers,
        data=data,
        auth=HTTPBasicAuth(client_id, client_secret)
    )

    if response.status_code == 200:
        return response.json()
    else:
        return {"error": response.status_code, "message": response.text}
