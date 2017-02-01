OAuth2 PAM module
=================

This PAM module enables login with OAuth2 token instead of password.

## How to install it:

```bash
$ sudo apt-get install libcurl4-openssl-dev libpam0g-dev
$ git submodule init
$ git submodule update
$ make
$ sudo make install
```

## Configuration

```
auth sufficient pam_oauth2.so <tokeninfo url> <login field> key1=value2 key2=value2
account sufficient pam_oauth2.so
```

## How it works

Lets assume that configuration is looking like:

```
auth sufficient pam_oauth2.so https://foo.org/oauth2/tokeninfo?access_token= uid grp=tester
```

And somebody is trying to login with login=foo and token=bar.

pam\_oauth2 module will make http request https://foo.org/oauth2/tokeninfo?access_token=bar (tokeninfo url is simply concatenated with token) and check response code and content.

If the response code is not 200 - authentication will fail. After that it will check response content:

```json
{
  "access_token": "bar",
  "expires_in": 3598,
  "grp": "tester",
  "scope": [
    "uid"
  ],
  "token_type": "Bearer",
  "uid": "foo"
}
```

It will check that response is a valid JSON object and top-level object contains following key-value pairs:
```json
  "uid": "foo",
  "grp": "tester"
```

If some keys haven't been found or values don't match with expectation - authentication will fail.
