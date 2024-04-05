import requests
import sys
import argparse
import re
import time

# Function to perform login with basic authentication
def login(url, user, password, proxies=None):
    print("[+] Logging in as natas1...")
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

    getpass(response)

# Function to extract the password from the response
def getpass(response):
    print(f"[+] Getting the password...")
    time.sleep(1)
    content = response.text

    # Define regex pattern to find the password
    pattern = r"The password for natas2 is (.*)"
    # Using regex to search for password and extract it.
    passwd = (re.search(pattern, content).group(1)).split(" ")[0]
    print(f"The password of natas2 is: {passwd}")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Grabs the password of natas2 from an HTML comment.")
    parser.add_argument('-p', '--password', help='Password of natas1.', required=True, metavar='Password')
    parser.add_argument('-x', '--proxy', help='Sends requests through Burp Suite proxy at 127.0.0.1:8080.', action='store_true')
    args = parser.parse_args()

    # Define URL and authentication credentials
    url = 'http://natas1.natas.labs.overthewire.org'
    user = 'natas1'
    password = args.password
    proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

    # Check if proxy option is enabled and perform login
    if args.proxy:
        login(url, user, password, proxies=proxies)
    else:
        login(url, user, password)


if __name__ == "__main__":
    main()