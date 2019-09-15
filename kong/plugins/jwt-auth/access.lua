local validators = require "resty.jwt-validators"
local jwt = require "resty.jwt"
local cjson = require "cjson.safe"
local pl_pretty = require "pl.pretty"
local http = require "resty.http"

local EXPIRE_DELTA = 20
local MAX_PENDING_SLEEPS = 40
local PENDING_EXPIRE = 0.2
local PENDING_TABLE = {}

local lrucache = require "resty.lrucache.pureffi"
-- it is shared by all the requests served by each nginx worker process:
local worker_cache, err = lrucache.new(10000) -- allow up to 10000 items in the cache
if not worker_cache then
    return error("failed to create the cache: " .. (err or "unknown"))
end

local function unexpected_error(...)
    local pending_key = kong.ctx.plugin.pending_key
    if pending_key then
        worker_cache:delete(pending_key)
    end
    kong.log.err(...)
    kong.response.exit(502, { message = "An unexpected error ocurred" })
end

local function get_token(authorization)
    if authorization and #authorization > 0 then
        local from, to, err = ngx.re.find(authorization, "\\s*[Bb]earer\\s+(.+)", "jo", nil, 1)
        if from then
            return authorization:sub(from, to) -- Return token
        end
        if err then
            return unexpected_error(err)
        end
    end

    return nil
end

-- lru cache get operation with `pending` state support
local function worker_cache_get_pending(key)
    for i = 1, MAX_PENDING_SLEEPS do
        local token_data, stale_data = worker_cache:get(key)

        if not token_data or stale_data then
            return
        end

        if token_data == PENDING_TABLE then
            kong.log.debug("sleep 5ms")
            ngx.sleep(0.005) -- 5ms
        else
            return token_data
        end
    end
end

local function set_pending_state(key)
    kong.ctx.plugin.pending_key = key
    worker_cache:set(key, PENDING_TABLE, PENDING_EXPIRE)
end

local function clear_pending_state(key)
    kong.ctx.plugin.pending_key = nil
    worker_cache:delete(key)
end

local function set_cache(token, body)
    set_pending_state(token)

    local status, err, exp
    local jwt_obj = jwt:load_jwt(token)

    if not jwt_obj.valid then
        clear_pending_state(token)
        return kong.response.exit(401, { message = "Invalid token" })
    end

    local payload = jwt_obj.payload
    exp = payload.exp
    payload.refresh_token = body.refreshToken

    kong.log.debug("save token in cache")
    worker_cache:set(token, payload,
        exp - ngx.now() - EXPIRE_DELTA)
end

local function request_to_upstream_set_cache(url, jsonBody)
    local httpc = http.new()
    local headers = {
        ["Content-Type"] = "application/json"
    }

    local res, err = httpc:request_uri(url, {
        method = "POST",
        body = jsonBody,
        headers = headers,
        ssl_verify = false
    })

    if err then
        return error("failed to create the cache: " .. (err or "unknown"))
    end

    if res.status >= 300 then
        ngx.status = res.status
        ngx.header.content_type = "application/json; charset=utf-8"
        ngx.say(res.body)
        return ngx.exit(res.status)
    end

    local json, err = cjson.decode(res.body)
    if err then
        ngx.log(ngx.ERR, err)
        return nil, "JSON decode error: " .. err
    end

    set_cache(json.token, json)
    ngx.status = ngx.HTTP_OK
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.say(res.body)
    return ngx.exit(ngx.HTTP_OK)
end

local function access_handler(self, conf)
    local authorization = ngx.var.http_authorization
    local token = get_token(authorization)

    local method = ngx.req.get_method()
    local path = ngx.var.uri
    kong.log.debug("path : ", path)

    if method == "POST" and path == conf.login_endpoint then
        ngx.req.read_body()
        local body = ngx.req.get_body_data()
        if not body then
            ngx.log(ngx.ERR, "body not found")
        end

        ngx.log(ngx.DEBUG, "Request Body :::: ", body)
        cjson.decode_array_with_array_mt(true)
        local req_body = cjson.decode(body)
        cjson.decode_array_with_array_mt(false)

        if req_body.email and req_body.password then
            req_body = cjson.encode({ email = req_body.email, password = req_body.password })
        else
            req_body = cjson.encode({})
        end

        return request_to_upstream_set_cache(conf.upstream_url .. conf.login_endpoint, req_body)
    end

    if not token then
        return kong.response.exit(401, { message = "Failed to get bearer token from Authorization header" })
    end

    local token_data = worker_cache_get_pending(token)
    if token_data then
        if token_data.exp - conf.check_jwt_expire <= ngx.now() then
            kong.log.debug("Requesting for new token")
            clear_pending_state(token)
            local req_body = cjson.encode({ grantType = "refresh_token", refreshToken = token_data.refresh_token})
            return request_to_upstream_set_cache(conf.upstream_url .. conf.refresh_token_endpoint, req_body)
        end
        kong.log.debug("Allow Success, Request already validate fron cache")
        return
    else
        return kong.response.exit(401, { message = "Bad token" })
    end
end

return function(self, conf)
    access_handler(self, conf)
end
