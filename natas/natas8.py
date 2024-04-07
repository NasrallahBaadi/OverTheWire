import requests
import sys
import argparse
import re
import time
import base64

# Function to perform login with basic authentication
def login(url, user, password, proxies=None):
    print("[+] Logging in as natas8...")
    time.sleep(1)
    # Performing basic authentication with the "auth" argument.
    response = requests.get(url, auth=(user, password), proxies=proxies)
    if response.status_code == 200:
        print("[+] Logged in successfully!")
        time.sleep(1)
    else:
        print("[-] Failed to log in :(")
        print("[-] Exiting...")
        sys.exit(1)

def grabsecret(url, user, password, proxies=None):

    print("[+] Grabbing the encoded secret...")
    time.sleep(1)

    url = url + "/index-source.html"
    response = requests.get(url, auth=(user, password), proxies=proxies)
    content = response.text
    # print(content)

    pattern = r"[a-z0-9]{32}"
    # Using regex to search for password and extract it.
    secret = (re.search(pattern, content)).group()
    print(f"[+] The encoded secret is: {secret}")
    time.sleep(1)
    
    return decodesecret(secret)

def decodesecret(hsecret):
    print("[+] Decoding the secret...")
    time.sleep(1)
    # Decoding from hex
    reversedsecret = bytes.fromhex(hsecret).decode('utf-8')
    # Reversing the string
    bs64secret = reversedsecret[::-1]
    # Decoding from base64
    secret = base64.b64decode(bs64secret).decode("utf-8")
    print(f"[+] The secret is: {secret}")
    time.sleep(1)
    return secret

# Function to extract the password from the response
def getpass(url, user, password, secret, proxies=None):
    print(f"[+] Getting the password...")
    time.sleep(1)

    data = {"secret": secret, "submit": "Submit+Query"}
    response = requests.post(url, auth=(user, password), data=data , proxies=proxies)
    content = response.text

    # Define regex pattern to find the password
    pattern = r"The password for natas9 is (.*)"
    # Using regex to search for password and extract it.
    passwd = (re.search(pattern, content).group(1)).split("<")[0]
    print(f"[+] The password of natas9 is: {passwd}")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Grabs the password of natas9 through information disclosure.")
    parser.add_argument('-p', '--password', help='Password of natas8.', required=True, metavar='Password')
    parser.add_argument('-x', '--proxy', help='Sends requests through Burp Suite proxy at 127.0.0.1:8080.', action='store_true')
    args = parser.parse_args()

    # Define URL and authentication credentials
    url = 'http://natas8.natas.labs.overthewire.org'
    user = 'natas8'
    password = args.password
    proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

    # Check if proxy option is enabled and perform login
    if args.proxy:
        login(url, user, password, proxies=proxies)
        secret = grabsecret(url, user, password, proxies=proxies)
        getpass(url, user, password, secret, proxies=proxies)

    else:
        login(url, user, password)
        secret = grabsecret(url, user, password)
        getpass(url, user, password, secret)
    
if __name__ == "__main__":
    main()