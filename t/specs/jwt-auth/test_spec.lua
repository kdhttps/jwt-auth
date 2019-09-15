local utils = require "test_utils"
local sh, stdout, stderr, sleep, sh_ex, sh_until_ok =
utils.sh, utils.stdout, utils.stderr, utils.sleep, utils.sh_ex, utils.sh_until_ok

local kong_utils = require "kong_utils"
local JSON = require "JSON"

local host_git_root = os.getenv "HOST_GIT_ROOT"
local git_root = os.getenv "GIT_ROOT"
local test_root = host_git_root .. "/t/specs/jwt-auth"

local function setup()
    _G.ctx = {}
    local ctx = _G.ctx
    ctx.finalizeres = {}
    ctx.host_git_root = host_git_root

    ctx.print_logs = true
    finally(function()
        if ctx.print_logs then
            if ctx.kong_id then
                sh("docker logs ", ctx.kong_id, " || true") -- don't fail
            end
            if ctx.backend_id then
                sh("docker logs ", ctx.backend_id, " || true") -- don't fail
            end
        end

        local finalizeres = ctx.finalizeres
        -- call finalizers in revers order
        for i = #finalizeres, 1, -1 do
            xpcall(finalizeres[i], debug.traceback)
        end
    end)


    kong_utils.docker_unique_network()
    kong_utils.kong_postgress_custom_plugins {
        plugins = {
            ["jwt-auth"] = host_git_root .. "/kong/plugins/jwt-auth"
        },
        modules = {
            ["resty/lrucache.lua"] = host_git_root .. "/third-party/lua-resty-lrucache/lib/resty/lrucache.lua",
            ["resty/lrucache/pureffi.lua"] = host_git_root .. "/third-party/lua-resty-lrucache/lib/resty/lrucache/pureffi.lua",
            ["resty/jwt.lua"] = host_git_root .. "/third-party/lua-resty-jwt/lib/resty/jwt.lua",
            ["resty/evp.lua"] = host_git_root .. "/third-party/lua-resty-jwt/lib/resty/evp.lua",
            ["resty/jwt-validators.lua"] = host_git_root .. "/third-party/lua-resty-jwt/lib/resty/jwt-validators.lua",
            ["resty/hmac.lua"] = host_git_root .. "/third-party/lua-resty-hmac/lib/resty/hmac.lua",
        },
        host_git_root = host_git_root,
    }
    kong_utils.backend()
end

local function configure_service_route(service_name, service, route)
    service_name = service_name or "demo-service"
    service = service or "backend"
    route = route or "backend.com"

    print "create a Sevice"
    local res, err = sh_until_ok(10,
        [[curl --fail -sS -X POST --url http://localhost:]],
        ctx.kong_admin_port, [[/services/ --header 'content-type: application/json' --data '{"name":"]], service_name, [[","url":"http://]],
        service, [["}']])

    local create_service_response = JSON:decode(res)

    print "create a Route"
    local res, err = sh_until_ok(10,
        [[curl --fail -i -sS -X POST  --url http://localhost:]],
        ctx.kong_admin_port, [[/services/]], service_name, [[/routes --data 'hosts[]=]], route, [[']])

    return create_service_response
end

local function configure_plugin(create_service_response, plugin_config)
    local payload = {
        name = "jwt-auth",
        config = plugin_config,
        service = {
            id = create_service_response.id
        }
    }
    local payload_json = JSON:encode(payload)

    print "enable plugin for the Service"
    local res, err = sh_ex([[
        curl -v -i -sS -X POST  --url http://localhost:]], ctx.kong_admin_port,
        [[/plugins/ ]],
        [[ --header 'content-type: application/json;charset=UTF-8' --data ']], payload_json, [[']])
end

test("With and Without token", function()
    setup()

    local create_service_response = configure_service_route()

    print "test it works"
    sh_ex([[curl -i -sS -X GET --url http://localhost:]],
        ctx.kong_proxy_port, [[/v1/user --header 'Host: backend.com']])

    configure_plugin(create_service_response,
        {
            login_endpoint = '/tokens',
            refresh_token_endpoint = '/tokens',
            upstream_url = 'http://backend',
            check_jwt_expire = 60
        })

    print "Test without"
    local res, err = sh_ex([[curl -i -sS -X GET --url http://localhost:]],
        ctx.kong_proxy_port, [[/ --header 'Host: backend.com']])
    assert(res:find("401", 1, true))

    local res, err = sh_ex([[curl -i -sS -X GET --url http://localhost:]],
        ctx.kong_proxy_port, [[/v1/user --header 'Host: backend.com']])
    assert(res:find("401", 1, true))

    local res, err = sh_ex([[
        curl -v -i -sS -X POST --url http://localhost:]], ctx.kong_proxy_port,
        [[/tokens --header 'Host: backend.com'  --header 'content-type: application/json;charset=UTF-8' --data '{"email":"invalid", "password": "invalid"}']]
    )
    assert(res:find("401", 1, true))

    print "Get login and Obtain token"
    local res, err = sh_ex([[
        curl -sS -X POST --url http://localhost:]], ctx.kong_proxy_port,
        [[/tokens --header 'Host: backend.com'  --header 'content-type: application/json' --data '{"email":"admin", "password": "admin"}']]
    )
    local login_response = JSON:decode(res)

    print "Request with token"
    local res, err = sh_ex([[curl -i -sS -X GET --url http://localhost:]],
        ctx.kong_proxy_port, [[/v1/user --header 'Host: backend.com' --header 'Authorization: Bearer ]], login_response.token, [[']])
    assert(res:find("200", 1, true))

    local res, err = sh_ex([[curl -i -sS -X GET --url http://localhost:]],
        ctx.kong_proxy_port, [[/v1/user --header 'Host: backend.com' --header 'Authorization: Bearer ]], login_response.token, [[']])
    assert(res:find("200", 1, true))

    local res, err = sh_ex([[curl -i -sS -X GET --url http://localhost:]],
        ctx.kong_proxy_port, [[/v1/user --header 'Host: backend.com' --header 'Authorization: Bearer ]], login_response.token, [[']])
    assert(res:find("200", 1, true))

    sh("sleep 140")

    print "Get New JWT before expire old one"
    local res, err = sh_ex([[
        curl -sS -X GET --url http://localhost:]], ctx.kong_proxy_port,
        [[/v1/user --header 'Host: backend.com'  --header 'content-type: application/json' --header 'Authorization: Bearer ]], login_response.token, [[']])
    local login_response = JSON:decode(res)

    local res, err = sh_ex([[curl -i -sS -X GET --url http://localhost:]],
        ctx.kong_proxy_port, [[/v1/user --header 'Host: backend.com' --header 'Authorization: Bearer ]], login_response.token, [[']])
    assert(res:find("200", 1, true))

    local res, err = sh_ex([[curl -i -sS -X GET --url http://localhost:]],
        ctx.kong_proxy_port, [[/v1/user --header 'Host: backend.com' --header 'Authorization: Bearer ]], login_response.token, [[']])
    assert(res:find("200", 1, true))

    print "JWT is totally expired time and also from kong cache"
    sh("sleep 200")
    local res, err = sh_ex([[curl -i -sS -X GET --url http://localhost:]],
        ctx.kong_proxy_port, [[/v1/user --header 'Host: backend.com' --header 'Authorization: Bearer ]], login_response.token, [[']])
    assert(res:find("401", 1, true))

    local res, err = sh_ex([[curl -i -sS -X GET --url http://localhost:]],
        ctx.kong_proxy_port, [[/v1/user --header 'Host: backend.com' --header 'Authorization: Bearer ]], login_response.token, [[']])
    assert(res:find("401", 1, true))

--    ctx.print_logs = false -- comment it out if want to see logs
end)