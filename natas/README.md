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
