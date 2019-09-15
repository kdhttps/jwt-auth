# jwt-auth

JWT Authenticaion plugin for Kong Lua plugin

# Setup

## Clone

Plugin use some third party libs so need to clone repository recursively. 
With version 2.13 of Git and later
```
git clone --recurse-submodules git@github.com:3gthtech/jwt-auth.git
```

With version 1.9 of Git up until version 2.12
```
git clone --recursive git@github.com:3gthtech/jwt-auth.git
```

## Kong Configuration

### Take a file from your local clone repo `/third-party` folder.

```
$ sudo cp -R /third-party/lua-resty-lrucache/lib/resty/ /usr/local/share/lua/5.1/resty

$ sudo cp /third-party/lua-resty-lrucache/lib/resty/lrucache.lua /usr/local/share/lua/5.1/resty

$ sudo cp -a /third-party/lua-resty-jwt/lib/resty/. /usr/local/share/lua/5.1/resty

$ sudo cp -a /third-party/lua-resty-hmac/lib/resty/. /usr/local/share/lua/5.1/resty
```

### Install our `jwt-auth` with kong plugin

```
$ sudo cp -R /kong/plugins/jwt-auth /usr/local/share/lua/5.1/kong/plugins
```

Enable plugin by adding plugin name in `/etc/kong/kong.conf`

```
plugins = bundled, jwt-auth
```

`bundled` is for kong default plugins. After adding this name, restart kong `sudo kong restart`.

# Configuration

1. Add service

```
$ curl --fail -sS -X POST --url http://localhost:8001/services/ --header 'content-type: application/json' --data '{"name":"demo-service","url":"http://backend"}'
```

2. Add Route

```
$ curl --fail -i -sS -X POST  --url http://localhost:8001/services/demo-service/routes --data 'hosts[]=backend.com'
```

Before add plugin check proxy with your upstream API

```
curl -i -sS -X GET --url http://localhost:8000/v1/user --header 'Host: backend.com'
```

3. Add Plugin

```
$ curl -v -i -sS -X POST  --url http://localhost:8001/plugins/  --header 'content-type: application/json;charset=UTF-8' --data '{"config":{"check_jwt_expire":60,"login_endpoint":"/tokens","refresh_token_endpoint":"/tokens","upstream_url":"http://localhost:8081"},"name":"jwt-auth","service":{"id":"dc862e47-4475-4cb0-ac48-9f9d4f1eb869"}}'
```

Schema details

| Title | Description |
|-------|-------------|
| upstream_url | Your upstream service example: `http://localhost:8081` |
| login_endpoint | Authotization endpoint from your upstream service from where you get JWT. Example: `/tokens` |
| refresh_token_endpoint | Refresh token endpoint from your upstream service from where you get new JWT by refresh token. Example: `/tokens` |
| check_jwt_expire | Time in second to check old JWT expire time before it expired. This time in seconds. Default value is 60 seconds. |

# Usage

Request to login_endpoint through kong proxy to upstream service.

```
$ curl -sS -X POST --url http://localhost:8000/tokens --header 'Host: backend.com'  --header 'content-type: application/json' --data '{"email":"admin@gmail.com", "password": "admin"}'
```

Get a new token from this and request to access protected resources.

```
curl -i -sS -X GET --url http://localhost:8000/v1/user --header 'Host: backend.com' --header 'Authorization: Bearer <your_jwt_token>'
```

# Test

[Test cases](./t)
