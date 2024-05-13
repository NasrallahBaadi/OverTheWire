# OverTheWire Natas

Natas teaches the basics of server-side web-security.

## Usage

```bash
python natas.py -p password
```

To send the request to Burp Suite proxy, simply add `-x` option.

```bash
python natas.py -p password -x
```

## Natas1

The password is located in a comment in the HTML source code.

## Natas2

The password can be found in a comment in the HTML source code.

## Natas3

The password is in a text file located at `files` directory.

## Natas4

The robots.txt file reveals a secret directory that contains a text file with the password.

## Natas5

We add a custom `referer` header to get the password.

## Natas6

We manipulate a cookie to get the password.

## Natas7

To get the password we find a secret string through an information disclosure and send the secret via a post request.

## Natas8

To get the password we exploit a `LFI` (**Local File Inclusion**) to read the password file.

## Natas9

A secret string is required to get the password. We find the secret but it's encrypted through multiple layers, we easily decrypt it and get the password.

## Natas10

We get the password by exploiting a `Command injection` vulnerability to read the password file.

## Natas11

We still use the command injection vulnerability but with a different payload to read the password file.

## Natas12

The cookie used is XOR encoded with a secret key, we use the plain text cookie with the encoded one to calculate the key, and use the key to encode a modified cookie that we use to get the password

## Natas13

We exploit an upload form and upload a web shell and use it to read the password file.

## Natas14

The upload page uses a MIME-type filter that we need to bypass to upload a file and read the password.

## Natas15

We find a login form vulnerable to sql injection, we bypass the check and get the password.

## Natas16

There a search form vulnerable to blind sql injection, we use a special payload and brute force for the password.

## Natas17

We find a blind command injection vulnerability so we brute force the password.

## Natas18

The search form doesn't return any output so we use time-based sql injection to get the password.

## Natas19

The website uses clear text cookies, we brute force for the admin's cookie and get the password

## Natas20

The cookies are encrypted using hex, we brute force the admin cookie with encrypting it in every request.

## Natas21

The session is saved in a file and the website check for a special data in the file to determine admin, we use a vulnerable `name` parameter to inject that data in the file and get the password.

## Natas22

We exploit the co-located websites by using one of the experimental page's functionality to add an unintended variable.

## Natas23

We send an empty parameter and read the password from the response before we get redirected.

## Natas24

We trick a password check form to get the password.

## Natas25

We exploit the insecure `strcmp` function in php to bypass a check.

## Natas26

We exploit a Local File Inclusion with Log Poisoning.

## Natas27

We exploit an insecure deserialization of a cookie to write a php file and read the password.

## Natas28

We exploit a length limit vulnerability in mysql.

## Natas29

## Natas30

## Natas31

## Natas32

## Natas33

## Natas34
