## Oauth2 SSO Wrapper

SSO Login Use Oauth2


### How to use it
1. install golang
2.  `make & cd ./build/1.0/main` to run
3.  edit `./build/1.0/main/config.json`
4   `./main` to run
4.  Proxy  http://some_host/sso/* to http://sso_host/sso/*
5.  run your  http://some_host/sso/login and http://some_host/sso/logout to test

### More

1. `/sso/login`

login form oauth2 provider and write access_token to current domain cookies
    
2. `/sso/logout`

revoke form oauth2 provider and  clear access_token to current domain cookies
