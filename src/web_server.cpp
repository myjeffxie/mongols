#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <regex>

#include "lib/hash/hash_engine.hpp"
#include "lib/mustache.hpp"
#include "response.hpp"
#include "util.hpp"
#include "version.hpp"
#include "web_server.hpp"

namespace mongols
{

    std::string web_server::dir_index_template = std::move("<!DOCTYPE html>"
                                                           "<html>"
                                                           "<head>"
                                                           "<title>"
                                                           "Welcome to mongols web_server!"
                                                           "</title>"
                                                           "<style>"
                                                           "</style>"
                                                           "</head>"
                                                           "<body>"
                                                           "<div>"
                                                           "<h3>Directory index</h3>"
                                                           "<ul>"
                                                           "{{#list}}"
                                                           "<li>"
                                                           "<a href=\"{{href}}\">{{name}}</a>"
                                                           "</li>"
                                                           "{{/list}}"
                                                           "</ul>"
                                                           "</div>"
                                                           "</body>"
                                                           "</html>");

    web_server::web_server(const std::string &host, int port, int timeout, size_t buffer_size, size_t thread_size, size_t max_body_size, int max_event_size)
        : last_cb(nullptr), root_path(), mime_type(), file_mmap(), server(0), list_directory(false), enable_mmap(false)
    {
        this->server = new http_server(host, port, timeout, buffer_size, thread_size, max_body_size, max_event_size);
    }

    web_server::~web_server()
    {
        for (auto &i : this->file_mmap)
        {
            munmap(i.second.first, i.second.second.st_size);
        }
        if (this->server)
        {
            delete this->server;
        }
    }

    void web_server::run(const std::function<bool(const mongols::request &)> &req_filter)
    {
        if (this->enable_mmap)
        {
            this->server->run(req_filter, std::bind(&web_server::res_filter_with_mmap, this, std::placeholders::_1, std::placeholders::_2));
        }
        else
        {
            this->server->run(req_filter, std::bind(&web_server::res_filter, this, std::placeholders::_1, std::placeholders::_2));
        }
    }

    void web_server::set_last_cb(const last_cb_t &f)
    {
        this->last_cb = f;
    }

    void web_server::res_filter(const mongols::request &req, mongols::response &res)
    {
        std::string host = req.headers.at("Host");
        auto iter = this->root_path.find(host);
        if (iter != this->root_path.end())
        {
            std::string path = std::move(this->root_path[host] + req.uri);
            struct stat st;
            if (stat(path.c_str(), &st) == 0)
            {
                if (S_ISREG(st.st_mode))
                {
                    int ffd = open(path.c_str(), O_RDONLY | O_NONBLOCK);
                    if (ffd > 0)
                    {
                        if (posix_fadvise(ffd, 0, 0, POSIX_FADV_SEQUENTIAL) == 0)
                        {
                            char ffd_buffer[st.st_size];
                        http_read:
                            if (read(ffd, ffd_buffer, st.st_size) < 0)
                            {
                                if (errno == EAGAIN || errno == EINTR)
                                {
                                    goto http_read;
                                }

                                close(ffd);
                                goto http_500;
                            }
                            else
                            {
                                res.status = 200;
                                res.headers.find("Content-Type")->second = std::move(this->get_mime_type(path));
                                time_t now = time(0);
                                res.headers.insert(std::move(std::make_pair(std::move("Last-Modified"), mongols::http_time(&now))));
                                res.content.assign(ffd_buffer, st.st_size);
                                close(ffd);
                            }
                        }
                        else
                        {
                            close(ffd);
                            goto http_500;
                        }
                    }
                    else
                    {
                    http_500:
                        res.status = 500;
                        res.content = std::move("Internal Server Error");
                    }
                }
                else if (S_ISDIR(st.st_mode))
                {
                    if (this->list_directory)
                    {
                        res.content = std::move(this->create_list_directory_response(req, path));
                        res.status = 200;
                    }
                    else
                    {
                        res.status = 403;
                        res.content = std::move("Forbidden");
                    }
                }
            }
            else if (this->last_cb)
            {
                this->last_cb(req, res);
            }
        }
    }

    std::string web_server::get_mime_type(const std::string &path)
    {
        std::string::size_type p;
        if (this->mime_type.empty() || (p = path.find_last_of(".")) == std::string::npos)
        {
            return "application/octet-stream";
        }
        return this->mime_type[path.substr(p + 1)];
    }

    void web_server::set_root_path(const std::string &host, const std::string &path)
    {
        this->root_path[host] = path;
    }

    void web_server::set_mime_type_file(const std::string &path)
    {
        std::ifstream input(path);
        if (input)
        {
            std::string line;
            std::vector<std::string> m;
            while (std::getline(input, line))
            {
                if (line.front() != '#' && !line.empty())
                {
                    split(line, " ", m);
                    int p = 0;
                    for (auto item : m)
                    {
                        if (p++ > 0)
                        {
                            this->mime_type[item] = m[0];
                        }
                    }
                    m.clear();
                }
            }
        }
    }

    std::string web_server::create_list_directory_response(const mongols::request &req, const std::string &path)
    {
        kainjow::mustache::mustache render_engine(web_server::dir_index_template);
        kainjow::mustache::data list{kainjow::mustache::data::type::list};

        DIR *dir = opendir(path.c_str());
        std::string tmp_path;
        size_t n = this->root_path[req.headers.at("Host")].size();
        struct dirent *entry;
        bool b = path.back() != '/';
        while ((entry = readdir(dir)) != NULL)
        {
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
            {
                tmp_path = b ? path + "/" + entry->d_name : path + entry->d_name;
                kainjow::mustache::data item;
                item.set("name", entry->d_name);
                item.set("href", tmp_path.substr(n));
                list.push_back(item);
            }
        }
        closedir(dir);
        return render_engine.render({"list", list});
    }

    void web_server::set_list_directory(bool b)
    {
        this->list_directory = b;
    }

    void web_server::set_enable_mmap(bool b)
    {
        this->enable_mmap = b;
    }

    void web_server::set_enable_lru_cache(bool b)
    {
        this->server->set_enable_lru_cache(b);
    }

    void web_server::res_filter_with_mmap(const mongols::request &req, mongols::response &res)
    {
        std::string host = req.headers.at("Host");
        auto iter = this->root_path.find(host);
        if (iter != this->root_path.end())
        {
            std::string path = std::move(this->root_path[host] + req.uri), mmap_key = std::move(hash_engine::md5(path));
            std::unordered_map<std::string, std::pair<char *, struct stat>>::const_iterator iter;
            struct stat st;
            if (stat(path.c_str(), &st) == 0)
            {
                if (S_ISREG(st.st_mode))
                {
                    if ((iter = this->file_mmap.find(mmap_key)) != this->file_mmap.end())
                    {
                        if (iter->second.second.st_mtime != st.st_mtime)
                        {
                            munmap(iter->second.first, iter->second.second.st_size);
                            this->file_mmap.erase(iter);
                            goto http_read;
                        }
                        res.status = 200;
                        res.headers.find("Content-Type")->second = std::move(this->get_mime_type(path));
                        res.content.assign(iter->second.first, iter->second.second.st_size);
                    }
                    else
                    {
                    http_read:
                        int ffd = open(path.c_str(), O_RDONLY | O_NONBLOCK);
                        if (ffd > 0)
                        {
                            char *mmap_ptr = (char *)mmap(0, st.st_size, PROT_READ, MAP_PRIVATE | MAP_POPULATE, ffd, 0);
                            if (mmap_ptr == MAP_FAILED)
                            {
                                close(ffd);
                                goto http_500;
                            }
                            else
                            {
                                close(ffd);
                                if (madvise(mmap_ptr, st.st_size, MADV_SEQUENTIAL) == 0)
                                {
                                    res.status = 200;
                                    res.headers.find("Content-Type")->second = std::move(this->get_mime_type(path));
                                    res.content.assign(mmap_ptr, st.st_size);
                                    this->file_mmap[mmap_key] = std::move(std::make_pair(mmap_ptr, st));
                                }
                                else
                                {
                                    munmap(mmap_ptr, st.st_size);
                                    goto http_500;
                                }
                            }
                        }
                        else
                        {
                        http_500:
                            res.status = 500;
                            res.content = std::move("Internal Server Error");
                        }
                    }
                }
                else if (S_ISDIR(st.st_mode))
                {
                    if (this->list_directory)
                    {
                        res.content = std::move(this->create_list_directory_response(req, path));
                        res.status = 200;
                    }
                    else
                    {
                        res.status = 403;
                        res.content = std::move("Forbidden");
                    }
                }
            }
            else if ((iter = this->file_mmap.find(mmap_key)) != this->file_mmap.end())
            {
                munmap(iter->second.first, iter->second.second.st_size);
                this->file_mmap.erase(iter);
            }
            if (this->last_cb)
            {
                this->last_cb(req, res);
            }
        }
    }

    void web_server::set_lru_cache_expires(long long expires)
    {
        this->server->set_lru_cache_expires(expires);
    }

    void web_server::set_lru_cache_size(size_t len)
    {
        this->server->set_lru_cache_size(len);
    }

    void web_server::set_uri_rewrite(const std::pair<std::regex, std::string> &p)
    {
        this->server->set_uri_rewrite(p);
    }

    bool web_server::set_openssl(const std::string &crt_file, const std::string &key_file, openssl::version_t v, const std::string &ciphers, long flags)
    {
        return this->server->set_openssl(crt_file, key_file, v, ciphers, flags);
    }

    void web_server::set_enable_blacklist(bool b)
    {
        this->server->set_enable_blacklist(b);
    }

    void web_server::set_enable_whitelist(bool b)
    {
        this->server->set_enable_whitelist(b);
    }
    void web_server::set_whitelist_file(const std::string &path)
    {
        this->server->set_whitelist_file(path);
    }
    void web_server::set_enable_security_check(bool b)
    {
        this->server->set_enable_security_check(b);
    }
    void web_server::set_shutdown(const tcp_server::shutdown_function &f)
    {
        this->server->set_shutdown(f);
    }
    void web_server::set_enable_dynamic(bool b)
    {
        this->server->set_enable_cache(b);
        this->server->set_enable_session(b);
    }
    void web_server::set_session_expires(long long expires)
    {
        this->server->set_session_expires(expires);
    }
    void web_server::set_cache_expires(long long expires)
    {
        this->server->set_cache_expires(expires);
    }
    void web_server::set_db_path(const std::string &path)
    {
        this->server->set_db_path(path);
    }
    void web_server::set_dynamic_uri_pattern(const std::regex &re)
    {
        this->server->set_dynamic_uri_pattern(re);
    }
} // namespace mongols
