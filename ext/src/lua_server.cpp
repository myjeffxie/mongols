#include "lua_server.hpp"
#include "lib/lua/kaguya_ext.hpp"
#include <mongols/util.hpp>
#include <functional>
#include <regex>

namespace mongols
{

    lua_server::lua_server(const std::string &host, int port, int timeout, size_t buffer_size, size_t thread_size, size_t max_body_size, int max_event_size)
        : vm(), server(0), root_path(), enable_bootstrap(false)
    {

        this->server = new http_server(host, port, timeout, buffer_size, thread_size, max_body_size, max_event_size);

        this->vm["mongols_request"].setClass(
            kaguya::UserdataMetatable<request>()
                .setConstructors<request()>()
                .addProperty("uri", &mongols::request::uri)
                .addProperty("method", &mongols::request::method)
                .addProperty("client", &mongols::request::client)
                .addProperty("user_agent", &mongols::request::user_agent)
                .addProperty("param", &mongols::request::param)
                .addFunction("has_header", &mongols::request::has_header)
                .addFunction("has_cookie", &mongols::request::has_cookie)
                .addFunction("has_form", &mongols::request::has_form)
                .addFunction("has_cache", &mongols::request::has_cache)
                .addFunction("has_session", &mongols::request::has_session)
                .addFunction("get_header", &mongols::request::get_header)
                .addFunction("get_cookie", &mongols::request::get_cookie)
                .addFunction("get_form", &mongols::request::get_form)
                .addFunction("get_session", &mongols::request::get_session)
                .addFunction("get_cache", &mongols::request::get_cache));
        this->vm["mongols_response"].setClass(
            kaguya::UserdataMetatable<response>()
                .addProperty("status", &mongols::response::status)
                .addProperty("content", &mongols::response::content)
                .addFunction("set_header", &mongols::response::set_header)
                .addFunction("set_session", &mongols::response::set_session)
                .addFunction("set_cache", &mongols::response::set_cache));

        mongols::lua_ext(this->vm);
    }

    lua_server::~lua_server()
    {
        if (this->server)
        {
            delete this->server;
        }
    }

    void lua_server::run(const std::string &package_path, const std::string &package_cpath)
    {
        if (!package_path.empty())
        {
            this->vm("package.path='" + package_path + "'.. package.path");
        }
        if (!package_cpath.empty())
        {
            this->vm("package.cpath='" + package_cpath + "'.. package.cpath");
        }

        this->server->run(std::bind(&lua_server::filter, this, std::placeholders::_1), std::bind(&lua_server::work, this, std::placeholders::_1, std::placeholders::_2));
    }

    bool lua_server::filter(const mongols::request &req)
    {
        return true;
    }

    void lua_server::work(const mongols::request &req, mongols::response &res)
    {
        this->vm["mongols_req"] = &req;
        this->vm["mongols_res"] = &res;
        this->vm.setErrorHandler([&](int errCode, const char *szError)
                                 {
                                     res.content = szError;
                                     res.status = 500;
                                 });
        this->vm.dofile(this->enable_bootstrap ? this->root_path + "/index.lua" : this->root_path + req.uri);
    }

    void lua_server::set_root_path(const std::string &path)
    {
        this->root_path = path;
    }

    void lua_server::set_db_path(const std::string &path)
    {
        this->server->set_db_path(path);
    }

    void lua_server::set_enable_bootstrap(bool b)
    {
        this->enable_bootstrap = b;
    }

    void lua_server::set_enable_cache(bool b)
    {
        this->server->set_enable_cache(b);
    }

    void lua_server::set_enable_session(bool b)
    {
        this->server->set_enable_session(b);
    }

    void lua_server::set_enable_lru_cache(bool b)
    {
        this->server->set_enable_lru_cache(b);
    }

    void lua_server::set_max_file_size(size_t len)
    {
        this->server->set_max_file_size(len);
    }

    void lua_server::set_max_open_files(int len)
    {
        this->server->set_max_open_files(len);
    }

    void lua_server::set_session_expires(long long expires)
    {
        this->server->set_session_expires(expires);
    }

    void lua_server::set_lru_cache_expires(long long expires)
    {
        this->server->set_lru_cache_expires(expires);
    }

    void lua_server::set_lru_cache_size(size_t len)
    {
        this->server->set_lru_cache_size(len);
    }

    void lua_server::set_write_buffer_size(size_t len)
    {
        this->server->set_write_buffer_size(len);
    }

    void lua_server::set_uri_rewrite(const std::pair<std::regex, std::string> &p)
    {
        this->server->set_uri_rewrite(p);
    }

    bool lua_server::set_openssl(const std::string &crt_file, const std::string &key_file, openssl::version_t v, const std::string &ciphers, long flags)
    {
        return this->server->set_openssl(crt_file, key_file, v, ciphers, flags);
    }

    void lua_server::set_enable_blacklist(bool b)
    {
        this->server->set_enable_blacklist(b);
    }

    void lua_server::set_enable_whitelist(bool b)
    {
        this->server->set_enable_whitelist(b);
    }
    void lua_server::set_whitelist_file(const std::string &path)
    {
        this->server->set_whitelist_file(path);
    }

    void lua_server::set_enable_security_check(bool b)
    {
        this->server->set_enable_security_check(b);
    }

    void lua_server::set_shutdown(const tcp_server::shutdown_function &f)
    {
        this->server->set_shutdown(f);
    }
} // namespace mongols