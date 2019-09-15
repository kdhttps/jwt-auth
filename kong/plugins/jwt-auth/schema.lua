return {
    no_consumer = true,
    fields = {
        upstream_url = { required = true, type = "string" },
        login_endpoint = { required = true, type = "string" },
        refresh_token_endpoint = { required = true, type = "string" },
        check_jwt_expire = { required = true, type = "number", default = 60 }
    }
}
