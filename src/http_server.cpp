#include <algorithm>
#include <chrono>
#include <functional>
#include <memory>
#include <sstream>
#include <sys/stat.h>
#include <utility>
#include <zlib.h>

#include "http_server.hpp"
#include "MPFDParser/Parser.h"
#include "lib/hash/hash_engine.hpp"
#include "lib/leveldb/cache.h"
#include "lib/jsoncons/json.hpp"
#include "tcp_threading_server.hpp"
#include "util.hpp"
#include "version.hpp"

#define form_urlencoded_type "application/x-www-form-urlencoded"
#define form_multipart_type "multipart/form-data"

#define TEMP_DIRECTORY "temp"
#define SESSION_NAME "SESSIONID"
#define LEVELDB_PATH "mongols_leveldb"

namespace mongols
{

    int http_server::zip_level = Z_BEST_SPEED;
    size_t http_server::zip_min_size = 1024, http_server::zip_max_size = 307200; /*1kb<size<300kb*/
    std::list<std::string> http_server::zip_mime_type = {"text/html", "text/css", "text/plain", "application/javascript", "text/xml", "image/jpeg"};

    http_server::http_server(const std::string &host, int port, int timeout, size_t buffer_size, size_t thread_size, size_t max_body_size, int max_event_size)
        : server(0), max_body_size(max_body_size), lru_cache_size(1024), db(0), db_options(), session_expires(3600), cache_expires(3600), lru_cache_expires(300), enable_session(false), enable_cache(false), enable_lru_cache(false), openssl_is_ok(false), db_path(LEVELDB_PATH), uri_rewrite_config(), lru_cache(0), route_map(), dynamic_uri_pattern(R"(.*\.(jsp|php|do|json|xml)$)")
    {
        if (thread_size > 0)
        {
            this->server = new tcp_threading_server(host, port, timeout, buffer_size, thread_size, max_event_size);
        }
        else
        {
            this->server = new tcp_server(host, port, timeout, buffer_size, max_event_size);
        }
        if (this->server)
        {
            this->db_options.create_if_missing = true;
        }
    }

    http_server::~http_server()
    {
        if (this->lru_cache)
        {
            delete this->lru_cache;
        }
        if (this->db)
        {
            delete this->db;
        }
        if (this->db_options.block_cache)
        {
            delete this->db_options.block_cache;
        }
        if (this->server)
        {
            delete this->server;
        }
    }

    void http_server::run(const std::function<bool(const mongols::request &)> &req_filter, const std::function<void(const mongols::request &, mongols::response &)> &res_filter)
    {
        tcp_server::handler_function g = std::bind(&http_server::work, this, std::cref(req_filter), std::cref(res_filter), std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5);
        if (this->enable_cache || this->enable_session)
        {
            leveldb::DB::Open(this->db_options, this->db_path, &this->db);
        }
        if (this->enable_lru_cache)
        {
            this->lru_cache = new lru11::Cache<std::string, std::shared_ptr<cache_t>>(this->lru_cache_size, 0);
        }
        this->server->run(g);
    }

    void http_server::run_with_route(const std::function<bool(const mongols::request &)> &req_filter)
    {
        auto res_filter = [&](const mongols::request &req, mongols::response &res)
        {
            std::vector<std::string> param;
            auto f = [&](const std::string &m)
            {
                return m == req.method;
            };
            for (auto &i : this->route_map)
            {
                std::smatch sm;
                if (std::find_if(i.method.begin(), i.method.end(), f) != i.method.end() && std::regex_match(req.uri, sm, *i.regex_engine))
                {
                    for (auto &item : sm)
                    {
                        param.push_back(item);
                    }
                    i.handler(req, res, param);
                    break;
                }
            }
        };
        this->run(req_filter, res_filter);
    }

    std::string http_server::create_response(mongols::response &res, bool b)
    {
        std::string output;
        output.append("HTTP/1.1 ").append(std::to_string(res.status)).append(" ").append(this->get_status_text(res.status)).append("\r\n");
        res.headers.insert(std::move(std::make_pair("Server", mongols_http_server_version)));
        if (b == KEEPALIVE_CONNECTION)
        {
            res.headers.insert(std::move(std::make_pair("Connection", "keep-alive")));
        }
        else
        {
            res.headers.insert(std::move(std::make_pair("Connection", "close")));
        }
        res.headers.insert(std::move(std::make_pair("Content-Length", std::to_string(res.content.size()))));
        for (auto &i : res.headers)
        {
            output.append(i.first).append(": ").append(i.second).append("\r\n");
        }
        output.append("\r\n").append(res.content);
        return output;
    }

    bool http_server::deflate_compress(std::string &content)
    {
        if (content.empty())
        {
            return false;
        }
        const char *src = content.c_str();
        const int src_size = content.size();
        size_t max_dst_size = compressBound(src_size);
        char compressed_data[max_dst_size];
        if (compress((Bytef *)compressed_data, &max_dst_size, (const Bytef *)src, src_size) == Z_OK)
        {
            content.assign(compressed_data, max_dst_size);
            return true;
        }
        return false;
    }

    bool http_server::gzip_compress(std::string &content)
    {

        const char *src = content.c_str();
        const int src_size = content.size();
        char out[src_size];
        z_stream strm;
        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;
        if (deflateInit2(&strm, http_server::zip_level, Z_DEFLATED, MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        {
            return false;
        }
        strm.next_in = (Bytef *)src;
        strm.avail_in = src_size;
        int have = 0, total = 0;
        do
        {
            strm.avail_out = src_size;
            strm.next_out = (Bytef *)out;
            if (::deflate(&strm, Z_FINISH) == Z_STREAM_ERROR)
            {
                return false;
            }
            have = src_size - strm.avail_out;
            total += have;
        } while (strm.avail_out == 0);
        if (deflateEnd(&strm) != Z_OK)
        {
            return false;
        }
        content.assign(out, total);
        return true;
    }

    std::string http_server::get_status_text(int status)
    {
        switch (status)
        {
        case 100:
            return "Continue";
        case 101:
            return "Switching Protocols";
        case 200:
            return "OK";
        case 201:
            return "Created";
        case 202:
            return "Accepted";
        case 203:
            return "Non-Authoritative Information";
        case 204:
            return "No Content";
        case 205:
            return "Reset Content";
        case 206:
            return "Partial Content";
        case 300:
            return "Multiple Choices";
        case 301:
            return "Moved Permanently";
        case 302:
            return "Found";
        case 303:
            return "See Other";
        case 304:
            return "Not Modified";
        case 305:
            return "Use Proxy";
        case 306:
            return "Switch Proxy";
        case 307:
            return "Temporary Redirect";
        case 400:
            return "Bad Request";
        case 401:
            return "Unauthorized";
        case 402:
            return "Payment Required";
        case 403:
            return "Forbidden";
        case 404:
            return "Not Found";
        case 405:
            return "Method Not Allowed";
        case 406:
            return "Not Acceptable";
        case 407:
            return "Proxy Authentication Required";
        case 408:
            return "Request Timeout";
        case 409:
            return "Conflict";
        case 410:
            return "Gone";
        case 411:
            return "Length Required";
        case 412:
            return "Precondition Failed";
        case 413:
            return "Request Entity Too Large";
        case 414:
            return "Request-URI Too Long";
        case 415:
            return "Unsupported Media Type";
        case 416:
            return "Requested Range Not Satisfiable";
        case 417:
            return "Expectation Failed";
        case 500:
            return "Internal Server Error";
        case 501:
            return "Not Implemented";
        case 502:
            return "Bad Gateway";
        case 503:
            return "Service Unavailable";
        case 504:
            return "Gateway Timeout";
        case 505:
            return "HTTP Version Not Supported";
        default:
            return ("Not supported status code.");
        }
    }

    std::string http_server::tolower(std::string &str)
    {
        std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c)
                       { return std::tolower(c); });
        return str;
    }

    bool http_server::upload(mongols::request &req, const std::string &body)
    {
        bool ret = false;
        if (body.size() != std::stol(req.headers["Content-Length"]))
        {
            return ret;
        }
        try
        {
            if ((is_dir(TEMP_DIRECTORY) || mkdir(TEMP_DIRECTORY, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == 0))
            {
                std::shared_ptr<MPFD::Parser> POSTParser(new MPFD::Parser());
                POSTParser->SetTempDirForFileUpload(TEMP_DIRECTORY);
                POSTParser->SetUploadedFilesStorage(MPFD::Parser::StoreUploadedFilesInFilesystem);
                POSTParser->SetMaxCollectedDataLength(this->max_body_size);
                POSTParser->SetContentType(req.headers["Content-Type"]);
                POSTParser->AcceptSomeData(body.c_str(), body.size());
                auto fields = POSTParser->GetFieldsMap();

                for (auto &item : fields)
                {
                    if (item.second->GetType() == MPFD::Field::TextType)
                    {
                        req.form.insert(std::make_pair(item.first, item.second->GetTextTypeContent()));
                    }
                    else
                    {
                        std::string upload_file_name = item.second->GetFileName(), ext;
                        std::string::size_type p = upload_file_name.find_last_of(".");
                        if (p != std::string::npos)
                        {
                            ext = std::move(upload_file_name.substr(p));
                        }
                        std::string temp_file = std::move(TEMP_DIRECTORY + ("/" + mongols::random_string(req.client + item.second->GetFileName()).append(ext)));
                        rename(item.second->GetTempFileName().c_str(), temp_file.c_str());
                        req.form.insert(std::make_pair(item.first, temp_file));
                    }
                }
                ret = true;
            }
        }
        catch (MPFD::Exception &err)
        {
            std::cout << err.GetError() << "\n";
        }
        return ret;
    }

    std::string http_server::work(
        const std::function<bool(const mongols::request &)> &req_filter, const std::function<void(const mongols::request &, mongols::response &)> &res_filter, const std::pair<char *, size_t> &input, bool &keepalive, bool &send_to_other, tcp_server::client_t &client, tcp_server::filter_handler_function &)
    {
        send_to_other = false;
        mongols::request req;
        mongols::response res;
        mongols::http_request_parser parser(req);
        bool enable_zip = false;
        http_server::zip_t zip_type = http_server::zip_t::unknown;
        if (parser.parse(input.first, input.second))
        {
            client.type = tcp_server::connection_t::HTTP;
            std::unordered_map<std::string, std::string>::const_iterator tmp_iterator;
            std::string &body = parser.get_body();
            req.client = client.ip;
            if ((tmp_iterator = req.headers.find("User-Agent")) != req.headers.end())
            {
                req.user_agent = tmp_iterator->second;
            }
            if (body.size() > this->max_body_size)
            {
                body.clear();
                res.content = std::move("Not allowed to upload this resource.");
                res.status = 500;
                keepalive = CLOSE_CONNECTION;
                return this->create_response(res, keepalive);
            }
            if (req_filter(req))
            {
                bool is_static_host = !std::regex_match(req.uri, this->dynamic_uri_pattern);
                if ((tmp_iterator = req.headers.find("Host")) == req.headers.end())
                {
                    res.content = std::move(this->get_status_text(403));
                    res.status = 403;
                    keepalive = CLOSE_CONNECTION;
                    return this->create_response(res, keepalive);
                }

                for (auto &rewrite_pattern : this->uri_rewrite_config)
                {
                    if (std::regex_match(req.uri, rewrite_pattern.first))
                    {
                        req.uri = std::move(regex_replace(req.uri, rewrite_pattern.first, rewrite_pattern.second));
                        break;
                    }
                }

                if (parser.keep_alive())
                {
                    keepalive = KEEPALIVE_CONNECTION;
                }

                if ((tmp_iterator = req.headers.find("Accept-Encoding")) != req.headers.end())
                {
                    if (tmp_iterator->second.find("gzip") != std::string::npos)
                    {
                        zip_type = zip_t::gzip;
                        enable_zip = true;
                    }
                    else if (tmp_iterator->second.find("deflate") != std::string::npos)
                    {
                        zip_type = zip_t::deflate;
                        enable_zip = true;
                    }
                }

                if ((tmp_iterator = req.headers.find("If-Modified-Since")) != req.headers.end() && difftime(time(0), mongols::parse_http_time((u_char *)tmp_iterator->second.c_str(), tmp_iterator->second.size())) <= this->lru_cache_expires)
                {
                    res.status = 304;
                    res.content.clear();
                    return this->create_response(res, keepalive);
                }

                std::string cache_k = std::move(hash_engine::md5(req.method + req.uri + "?" + req.param));
                if (!is_static_host && this->enable_lru_cache && req.method == "GET")
                {
                    if (this->lru_cache->contains(cache_k))
                    {
                        auto cache_ele = this->lru_cache->get(cache_k);
                        if (cache_ele->expired(this->lru_cache_expires))
                        {
                            this->lru_cache->remove(cache_k);
                        }
                        else
                        {
                            res.status = cache_ele->status;
                            res.content = cache_ele->content;
                            res.headers.find("Content-Type")->second = cache_ele->content_type;
                            res.headers.insert(std::move(std::make_pair("Last-Modified", mongols::http_time(&cache_ele->t))));
                            if (cache_ele->enable_zip)
                            {
                                if (cache_ele->zip_type == zip_t::deflate)
                                {
                                    res.headers.insert(std::move(std::make_pair("Content-Encoding", "deflate")));
                                }
                                else if (cache_ele->zip_type == zip_t::gzip)
                                {
                                    res.headers.insert(std::move(std::make_pair("Content-Encoding", "gzip")));
                                }
                            }
                            return this->create_response(res, keepalive);
                        }
                    }
                }

                if (!req.param.empty())
                {
                    mongols::parse_param(req.param, req.form);
                }

                std::string session_val, cache_v;

                if (!is_static_host && this->db)
                {
                    if (this->enable_session)
                    {
                        if ((tmp_iterator = req.headers.find("Cookie")) != req.headers.end())
                        {
                            mongols::parse_param(tmp_iterator->second, req.cookies, ';');
                            if ((tmp_iterator = req.cookies.find(SESSION_NAME)) != req.cookies.end())
                            {
                                session_val = tmp_iterator->second;
                                std::string v;
                                if (this->db->Get(leveldb::ReadOptions(), tmp_iterator->second, &v).ok())
                                {
                                    this->deserialize(v, req.session);
                                }
                                else
                                {
                                    this->db->Put(leveldb::WriteOptions(), tmp_iterator->second, this->serialize(req.session));
                                }
                            }
                        }
                        else
                        {
                            std::chrono::system_clock::time_point now_time = std::chrono::system_clock::now();
                            std::time_t expire_time = std::chrono::system_clock::to_time_t(now_time + std::chrono::seconds(this->session_expires));
                            std::string session_cookie;
                            session_cookie.append(SESSION_NAME).append("=").append(mongols::random_string("")).append("; HttpOnly; Path=/; Expires=").append(mongols::http_time(&expire_time));
                            if (this->openssl_is_ok)
                            {
                                session_cookie.append("; Secure");
                            }
                            res.headers.insert(std::move(std::make_pair("Set-Cookie", session_cookie)));
                        }
                    }

                    if (this->enable_cache)
                    {
                        if (this->db->Get(leveldb::ReadOptions(), cache_k, &cache_v).ok())
                        {
                            this->deserialize(cache_v, req.cache);
                        }
                        else
                        {
                            this->db->Put(leveldb::WriteOptions(), cache_k, this->serialize(req.cache));
                        }
                    }
                }

                if (!body.empty() && (tmp_iterator = req.headers.find("Content-Type")) != req.headers.end())
                {
                    if (tmp_iterator->second.find(form_multipart_type) != std::string::npos)
                    {
                        if (!this->upload(req, body))
                        {
                            res.status = 500;
                            res.content = "Upload is failed\n";
                            return this->create_response(res, CLOSE_CONNECTION);
                        }
                        body.clear();
                    }
                    else if (tmp_iterator->second.find(form_urlencoded_type) != std::string::npos)
                    {
                        mongols::parse_param(body, req.form);
                    }
                    else
                    {
                        req.form["__body__"] = std::move(body);
                    }
                }

                res_filter(req, res);
                if (res.status >= 400)
                {
                    keepalive = CLOSE_CONNECTION;
                }

                if (enable_zip)
                {
                    size_t len = res.content.size();
                    if ((len > http_server::zip_min_size && len <= http_server::zip_max_size))
                    {
                        const std::string &res_content_type = res.headers.find("Content-Type")->second;
                        auto zip_mime_type_iter = std::find_if(http_server::zip_mime_type.begin(), http_server::zip_mime_type.end(), [&](const std::string &item)
                                                               { return res_content_type.find(item) != std::string::npos; });
                        if (zip_mime_type_iter == http_server::zip_mime_type.end())
                        {
                            goto zip_error;
                        }
                        if (zip_type == zip_t::deflate)
                        {
                            if (this->deflate_compress(res.content))
                            {
                                res.headers.insert(std::move(std::make_pair("Content-Encoding", "deflate")));
                            }
                            else
                            {
                                goto zip_error;
                            }
                        }
                        else if (zip_type == zip_t::gzip)
                        {
                            if (this->gzip_compress(res.content))
                            {
                                res.headers.insert(std::move(std::make_pair("Content-Encoding", "gzip")));
                            }
                            else
                            {
                                goto zip_error;
                            }
                        }
                        else
                        {
                            goto zip_error;
                        }
                    }
                    else
                    {
                    zip_error:
                        enable_zip = false;
                        zip_type = http_server::zip_t::unknown;
                    }
                }

                std::unordered_map<std::string, std::string> *ptr = 0;
                if (!is_static_host && !res.session.empty() && this->db)
                {

                    if (!req.session.empty())
                    {
                        for (auto &i : res.session)
                        {
                            req.session[i.first] = std::move(i.second);
                        }
                        ptr = &req.session;
                    }
                    else
                    {
                        ptr = &res.session;
                    }
                    this->db->Put(leveldb::WriteOptions(), session_val, this->serialize(*ptr));
                }

                if (!is_static_host && !res.cache.empty() && this->db)
                {
                    if (!req.cache.empty())
                    {
                        for (auto &i : res.cache)
                        {
                            req.cache[i.first] = std::move(i.second);
                        }
                        ptr = &req.cache;
                    }
                    else
                    {
                        ptr = &res.cache;
                    }
                    this->db->Put(leveldb::WriteOptions(), cache_k, this->serialize(*ptr));
                }
                if (!is_static_host && this->enable_lru_cache && this->lru_cache_expires > 0 && req.method == "GET" && res.status == 200 && !req.param.empty())
                {
                    std::shared_ptr<cache_t> cache_ele = std::make_shared<cache_t>();
                    cache_ele->content = res.content;
                    cache_ele->status = res.status;
                    cache_ele->content_type = res.headers.find("Content-Type")->second;
                    cache_ele->enable_zip = enable_zip;
                    cache_ele->zip_type = zip_type;
                    this->lru_cache->insert(cache_k, cache_ele);
                    res.headers.insert(std::move(std::make_pair("Last-Modified", mongols::http_time(&cache_ele->t))));
                }
            }
        }

        return this->create_response(res, keepalive);
    }

    void http_server::set_session_expires(long long expires)
    {
        this->session_expires = expires;
    }

    void http_server::set_cache_expires(long long expires)
    {
        this->cache_expires = expires;
    }

    void http_server::set_enable_cache(bool b)
    {
        this->enable_cache = b;
    }

    void http_server::set_enable_session(bool b)
    {
        this->enable_session = b;
    }

    void http_server::set_max_file_size(size_t len)
    {
        this->db_options.max_file_size = len;
    }

    void http_server::set_max_open_files(int len)
    {
        this->db_options.max_open_files = len;
    }

    void http_server::set_write_buffer_size(size_t len)
    {
        this->db_options.write_buffer_size = len;
    }

    void http_server::set_cache_size(size_t len)
    {
        this->db_options.block_cache = leveldb::NewLRUCache(len);
    }

    void http_server::set_enable_compression(bool b)
    {
        if (!b)
        {
            this->db_options.compression = leveldb::kNoCompression;
        }
    }

    void http_server::set_db_path(const std::string &path)
    {
        this->db_path = path;
    }

    void http_server::set_uri_rewrite(const std::pair<std::regex, std::string> &p)
    {
        this->uri_rewrite_config.push_back(p);
    }

    void http_server::set_enable_lru_cache(bool b)
    {
        this->enable_lru_cache = b;
    }

    void http_server::set_lru_cache_expires(long long expires)
    {
        this->lru_cache_expires = expires;
    }

    void http_server::set_lru_cache_size(size_t len)
    {
        this->lru_cache_size = len;
    }

    bool http_server::set_openssl(const std::string &crt_file, const std::string &key_file, openssl::version_t v, const std::string &ciphers, long flags)
    {
        this->openssl_is_ok = this->server->set_openssl(crt_file, key_file, v, ciphers, flags);
        return this->openssl_is_ok;
    }

    void http_server::set_enable_blacklist(bool b)
    {
        this->server->set_enable_blacklist(b);
    }

    void http_server::set_enable_security_check(bool b)
    {
        this->server->set_enable_security_check(b);
    }

    void http_server::set_enable_whitelist(bool b)
    {
        this->server->set_enable_whitelist(b);
    }

    void http_server::set_whitelist_file(const std::string &path)
    {
        this->server->set_whitelist_file(path);
    }

    void http_server::set_shutdown(const tcp_server::shutdown_function &f)
    {
        this->server->set_shutdown(f);
    }

    std::string http_server::serialize(const std::unordered_map<std::string, std::string> &m)
    {
        jsoncons::json j(m);
        return j.as_string();
    }

    void http_server::deserialize(const std::string &str, std::unordered_map<std::string, std::string> &m)
    {
        jsoncons::json j = jsoncons::json::parse(str);
        m = std::move(j.as<std::unordered_map<std::string, std::string>>());
    }

    http_server::cache_t::cache_t()
        : status(200), t(time(0)), content_type(), content(), enable_zip(false), zip_type(http_server::zip_t::unknown)
    {
    }

    bool http_server::cache_t::expired(long long expires) const
    {
        return difftime(time(0), this->t) > expires;
    }

    void http_server::add_route(const std::list<std::string> &method, const std::string &pattern, const std::function<void(const mongols::request &, mongols::response &, const std::vector<std::string> &)> &hander)
    {
        route_t r;
        r.method = method;
        r.pattern = pattern;
        r.handler = hander;
        r.regex_engine = std::move(std::make_shared<std::regex>(pattern));
        this->route_map.emplace_back(std::move(r));
    }

    void http_server::set_dynamic_uri_pattern(const std::regex &re)
    {
        this->dynamic_uri_pattern = re;
    }

} // namespace mongols
