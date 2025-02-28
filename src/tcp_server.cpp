#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>

#include <algorithm>
#include <atomic>
#include <fstream>
#include <functional>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <regex>

#include "openssl.hpp"
#include "tcp_server.hpp"
#include "util.hpp"

namespace mongols
{

    std::atomic_bool tcp_server::done(true);
    int tcp_server::backlog = 511;
    size_t tcp_server::backlist_size = 1024;
    size_t tcp_server::max_connection_limit = 30;
    size_t tcp_server::backlist_timeout = 24 * 60 * 60;
    size_t tcp_server::max_send_limit = 5;
    size_t tcp_server::max_connection_keepalive = 60;

    tcp_server::setsockopt_function tcp_server::setsockopt_cb = nullptr;

    void tcp_server::signal_normal_cb(int sig, siginfo_t *, void *)
    {
        if (std::find(mongols::multi_process::ignore_signals.begin(), mongols::multi_process::ignore_signals.end(), sig) == mongols::multi_process::ignore_signals.end())
        {
            tcp_server::done = false;
        }
    }

    tcp_server::tcp_server(const std::string &host, int port, int timeout, size_t buffer_size, int max_event_size)
        : host(host), port(port), listenfd(0), max_event_size(max_event_size), server_is_ok(false), server_hints(), cleaning_fun(), whitelist_inotify(), server_epoll(0), buffer_size(buffer_size), thread_size(0), sid(0), timeout(timeout), sid_queue(), clients(), work_pool(0), blacklist(tcp_server::backlist_size), whitelist(), openssl_manager(), openssl_crt_file(), openssl_key_file(), openssl_is_ok(false), enable_blacklist(false), enable_whitelist(false), enable_security_check(false)
    {

        memset(&this->server_hints, 0, sizeof(this->server_hints));
        this->server_hints.ai_family = AF_UNSPEC;
        this->server_hints.ai_socktype = SOCK_STREAM;
        this->server_hints.ai_flags = AI_PASSIVE;

        struct addrinfo *server_info = 0;
        if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &this->server_hints, &server_info) != 0)
        {
            perror("getaddrinfo error");
            return;
        }
        else
        {
            this->server_is_ok = true;
        }

        this->listenfd = socket(server_info->ai_family, server_info->ai_socktype, server_info->ai_protocol);

        int on = 1;
        setsockopt(this->listenfd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));

        struct timeval send_timeout, recv_timeout;
        send_timeout.tv_sec = this->timeout;
        send_timeout.tv_usec = 0;
        setsockopt(this->listenfd, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout));

        recv_timeout.tv_sec = this->timeout;
        recv_timeout.tv_usec = 0;
        setsockopt(this->listenfd, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout));

        if (tcp_server::setsockopt_cb)
        {
            tcp_server::setsockopt_cb(this->listenfd);
        }

        bind(this->listenfd, server_info->ai_addr, server_info->ai_addrlen);

        freeaddrinfo(server_info);

        this->setnonblocking(this->listenfd);

        listen(this->listenfd, tcp_server::backlog);
    }

    tcp_server::~tcp_server()
    {
        if (this->work_pool)
        {
            delete this->work_pool;
        }
        if (this->cleaning_fun)
        {
            this->cleaning_fun();
        }
        if (this->listenfd)
        {
            close(this->listenfd);
        }
    }

    tcp_server::client_t::client_t()
        : type(tcp_server::connection_t::TCP), ip(), port(-1), t(time(0)), sid(0), uid(0), u_size(0), count(0), gid()
    {
        this->gid.push_back(0);
    }

    tcp_server::client_t::client_t(const std::string &ip, int port, size_t uid, size_t gid)
        : type(tcp_server::connection_t::TCP), ip(ip), port(port), t(time(0)), sid(0), uid(uid), u_size(0), count(0), gid()
    {
        this->gid.push_back(gid);
    }

    tcp_server::meta_data_t::meta_data_t()
        : client(), ssl()
    {
    }

    tcp_server::meta_data_t::meta_data_t(const std::string &ip, int port, size_t uid, size_t gid)
        : client(ip, port, uid, gid), ssl()
    {
    }

    tcp_server::black_ip_t::black_ip_t()
        : t(time(0)), count(1), disallow(false)
    {
    }

    void tcp_server::run(const handler_function &g)
    {
        if (!this->server_is_ok)
        {
            perror("server error");
            return;
        }

        struct sigaction act;
        auto config_signal = [&](const std::vector<int> &v)
        {
            for (const auto &item : v)
            {
                memset(&act, 0, sizeof(struct sigaction));
                sigemptyset(&act.sa_mask);
                act.sa_sigaction = tcp_server::signal_normal_cb;
                act.sa_flags = SA_SIGINFO;
                if (sigaction(item, &act, NULL) < 0)
                {
                    perror("sigaction error");
                    return false;
                }
            }
            return true;
        };
        if (!config_signal(multi_process::signals) || !config_signal(multi_process::ignore_signals))
        {
            return;
        }

        mongols::epoll epoll(this->max_event_size, -1);
        if (!epoll.is_ready())
        {
            perror("epoll error");
            return;
        }
        this->server_epoll = &epoll;
        if (!epoll.add(this->listenfd, EPOLLIN | EPOLLET))
        {
            perror("epoll listen error");
            return;
        }
        if (this->whitelist_inotify)
        {
            int whitelist_fd = this->whitelist_inotify->get_fd();
            this->setnonblocking(whitelist_fd);
            if (!epoll.add(whitelist_fd, EPOLLIN | EPOLLET) || !this->whitelist_inotify->watch(IN_MODIFY))
            {
                epoll.del(whitelist_fd);
                this->whitelist_inotify.reset();
            }
        }
        auto main_fun = std::bind(&tcp_server::main_loop, this, std::placeholders::_1, std::cref(g), std::ref(epoll));
        if (this->thread_size > 0)
        {
            this->work_pool = new mongols::thread_pool<std::function<bool()>>(this->thread_size);
        }
        while (tcp_server::done)
        {
            epoll.loop(main_fun);
        }
    }

    void tcp_server::set_shutdown(const shutdown_function &f)
    {
        this->cleaning_fun = f;
    }

    bool tcp_server::read_whitelist_file(const std::string &path)
    {
        if (mongols::is_file(path))
        {
            this->whitelist.clear();
            std::ifstream input(path);
            if (input)
            {
                std::string line;
                while (std::getline(input, line))
                {
                    mongols::trim(std::ref(line));
                    if (!line.empty() && line.front() != '#')
                    {
                        this->whitelist.push_back(std::regex(line));
                    }
                }
                return true;
            }
        }
        return false;
    }

    void tcp_server::set_whitelist_file(const std::string &path)
    {
        char path_buffer[PATH_MAX];
        char *tmp = realpath(path.c_str(), path_buffer);
        std::string real_path;
        if (tmp)
        {
            real_path = tmp;
        }
        else
        {
            return;
        }
        size_t p = real_path.find_last_of('/');
        std::string dir = real_path.substr(0, p), file_name = real_path.substr(p + 1);
        if (this->read_whitelist_file(real_path))
        {
            this->whitelist_inotify = std::make_shared<inotify>(dir);
            if (this->whitelist_inotify->get_fd() < 0)
            {
                this->whitelist_inotify.reset();
            }
            else
            {
                this->whitelist_inotify->set_cb([&, real_path, file_name](struct inotify_event *event)
                                                {
                                                    if (event->len > 0)
                                                    {
                                                        if (strncmp(event->name, file_name.c_str(), event->len) == 0 && event->mask & this->whitelist_inotify->get_mask())
                                                        {
                                                            this->read_whitelist_file(real_path);
                                                        }
                                                    }
                                                });
            }
        }
    }

    void tcp_server::setnonblocking(int fd)
    {
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    bool tcp_server::add_client(int fd, const std::string &ip, int port)
    {
        this->server_epoll->add(fd, EPOLLIN | EPOLLRDHUP | EPOLLET);
        auto pair = this->clients.insert(std::move(std::make_pair(fd, std::move(meta_data_t(ip, port, 0, 0)))));
        if (this->sid_queue.empty())
        {
            pair.first->second.client.sid = ++this->sid;
        }
        else
        {
            pair.first->second.client.sid = this->sid_queue.front();
            this->sid_queue.pop();
        }
        if (this->openssl_is_ok)
        {
            pair.first->second.ssl = std::make_shared<openssl::ssl>(this->openssl_manager->get_ctx());
            if (!this->openssl_manager->set_socket_and_accept(pair.first->second.ssl->get_ssl(), fd))
            {
                return false;
            }
        }
        return true;
    }

    void tcp_server::del_client(int fd)
    {
        this->server_epoll->del(fd);
        this->sid_queue.push(this->clients.find(fd)->second.client.sid);
        this->clients.erase(fd);
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }

    bool tcp_server::send_to_all_client(int fd, const std::string &str, const filter_handler_function &h)
    {
        std::vector<int> litter_fd;
        for (auto i = this->clients.begin(); i != this->clients.end();)
        {
            if (i->first != fd && h(i->second.client) && (this->openssl_is_ok ? this->openssl_manager->write(i->second.ssl->get_ssl(), str) < 0 : send(i->first, str.c_str(), str.size(), MSG_NOSIGNAL) < 0))
            {
                litter_fd.push_back(i->first);
            }
            else
            {
                ++i;
            }
        }
        for (auto &i : litter_fd)
        {
            this->del_client(i);
        }
        return false;
    }

    bool tcp_server::check_blacklist(const std::string &ip)
    {
        std::shared_ptr<black_ip_t> black_ip;
        if (this->blacklist.tryGet(ip, black_ip))
        {
            double diff = difftime(time(0), black_ip->t);
            if (black_ip->disallow)
            {
                if (diff < tcp_server::backlist_timeout)
                {
                    return false;
                }
                else
                {
                    black_ip->disallow = false;
                    black_ip->count = 1;
                    black_ip->t = time(0);
                }
            }

            if ((diff == 0 && black_ip->count > tcp_server::max_connection_limit) || (diff > 0 && black_ip->count / diff > tcp_server::max_connection_limit))
            {
                black_ip->t = time(0);
                black_ip->disallow = true;
                return false;
            }
            else
            {
                black_ip->count++;
            }
        }
        else
        {
            this->blacklist.insert(ip, std::make_shared<black_ip_t>());
        }
        return true;
    }

    bool tcp_server::check_whitelist(const std::string &ip)
    {
        return std::find_if(this->whitelist.begin(), this->whitelist.end(), [&](const std::regex &v)
                            { return std::regex_match(ip, v); }) != this->whitelist.end();
    }

    bool tcp_server::security_check(const tcp_server::client_t &client)
    {
        time_t now = time(0);
        double diff = difftime(now, client.t);
        if (diff > tcp_server::max_connection_keepalive || (diff == 0 && client.count > tcp_server::max_send_limit) || (diff > 0 && client.count / diff > tcp_server::max_send_limit))
        {
            return false;
        }
        return true;
    }

    bool tcp_server::work(int fd, const handler_function &g)
    {
        char buffer[this->buffer_size];
        bool rereaded = false;
    ev_recv:
        ssize_t ret = recv(fd, buffer, this->buffer_size, MSG_WAITALL);
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                if (!rereaded)
                {
                    rereaded = true;
                    goto ev_recv;
                }
            }
            else if (errno == EAGAIN)
            {
                return false;
            }
            goto ev_error;
        }
        else if (ret > 0)
        {
            std::pair<char *, size_t> input;
            input.first = &buffer[0];
            input.second = ret;
            filter_handler_function send_to_other_filter = [](const client_t &)
            {
                return true;
            };

            bool keepalive = CLOSE_CONNECTION, send_to_all = false;
            client_t &client = this->clients[fd].client;
            client.u_size = this->clients.size();
            client.count++;

            if (this->enable_security_check && !this->security_check(client))
            {
                goto ev_error;
            }

            std::string output = std::move(g(input, keepalive, send_to_all, client, send_to_other_filter));
            if (output.empty())
            {
                return false;
            }
            ret = send(fd, output.c_str(), output.size(), MSG_NOSIGNAL);
            if (ret > 0)
            {
                if (send_to_all)
                {
                    this->send_to_all_client(fd, output, send_to_other_filter);
                }
            }

            if (ret <= 0 || keepalive == CLOSE_CONNECTION)
            {
                goto ev_error;
            }
        }
        else
        {

        ev_error:
            this->del_client(fd);
        }

        return false;
    }

    bool tcp_server::ssl_work(int fd, const handler_function &g)
    {
        char buffer[this->buffer_size];
        ssize_t ret = 0;
        std::shared_ptr<openssl::ssl> ssl = this->clients[fd].ssl;
        bool rereaded = false;
    ev_recv:
        ret = this->openssl_manager->read(ssl->get_ssl(), buffer, this->buffer_size);
        if (ret < 0)
        {
            int err = SSL_get_error(ssl->get_ssl(), ret);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            {
                return false;
            }
            else if (err == SSL_ERROR_SYSCALL)
            {
                if (errno == EINTR)
                {
                    if (!rereaded)
                    {
                        rereaded = true;
                        goto ev_recv;
                    }
                }
                else if (errno == EAGAIN)
                {
                    return false;
                }
            }
            goto ev_error;
        }
        else if (ret > 0)
        {
            std::pair<char *, size_t> input;
            input.first = &buffer[0];
            input.second = ret;
            filter_handler_function send_to_other_filter = [](const client_t &)
            {
                return true;
            };

            bool keepalive = CLOSE_CONNECTION, send_to_all = false;
            client_t &client = this->clients[fd].client;
            client.u_size = this->clients.size();
            client.count++;

            if (this->enable_security_check && !this->security_check(client))
            {
                goto ev_error;
            }

            std::string output = std::move(g(input, keepalive, send_to_all, client, send_to_other_filter));
            if (output.empty())
            {
                return false;
            }
            ret = this->openssl_manager->write(ssl->get_ssl(), output);
            if (ret > 0)
            {
                if (send_to_all)
                {
                    this->send_to_all_client(fd, output, send_to_other_filter);
                }
            }

            if (ret <= 0 || keepalive == CLOSE_CONNECTION)
            {
                goto ev_error;
            }
        }
        else
        {

        ev_error:
            this->del_client(fd);
        }

        return false;
    }

    void tcp_server::main_loop(struct epoll_event *event, const handler_function &g, mongols::epoll &epoll)
    {
        if (event->data.fd == this->listenfd)
        {
            struct sockaddr_storage clientaddr;
            socklen_t clilen = sizeof(clientaddr);
            std::string clientip;
            int clientport = 0;
            int connfd = 0;
            do
            {
                connfd = accept(this->listenfd, (struct sockaddr *)&clientaddr, &clilen);
                if (connfd > 0)
                {
                    this->setnonblocking(connfd);

                    if (!this->get_client_address(&clientaddr, clientip, clientport))
                    {
                        goto accept_error;
                    }
                    if (this->enable_blacklist && !this->check_blacklist(clientip))
                    {
                    accept_error:
                        shutdown(connfd, SHUT_RDWR);
                        close(connfd);
                        break;
                    }
                    if (this->enable_whitelist && !this->check_whitelist(clientip))
                    {
                        goto accept_error;
                    }
                    if (!this->add_client(connfd, clientip, clientport))
                    {
                        this->del_client(connfd);
                        break;
                    }
                }
            } while (connfd > 0);
        }
        else if (event->events & EPOLLIN)
        {
            if (this->whitelist_inotify && event->data.fd == this->whitelist_inotify->get_fd())
            {
                this->whitelist_inotify->run();
            }
            else if (this->openssl_is_ok)
            {
                this->ssl_work(event->data.fd, g);
            }
            else
            {
                this->work(event->data.fd, g);
            }
        }
        else
        {
            this->del_client(event->data.fd);
        }
    }

    size_t tcp_server::get_buffer_size() const
    {
        return this->buffer_size;
    }

    bool tcp_server::get_client_address(struct sockaddr_storage *address, std::string &ip, int &port)
    {
        if (address->ss_family == AF_INET)
        {
            struct sockaddr_in *clientaddr_v4 = (struct sockaddr_in *)address;
            char clistr[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &clientaddr_v4->sin_addr, clistr, INET_ADDRSTRLEN))
            {
                ip = clistr;
                port = ntohs(clientaddr_v4->sin_port);
                return true;
            }
        }
        else if (address->ss_family == AF_INET6)
        {
            struct sockaddr_in6 *clientaddr_v6 = (struct sockaddr_in6 *)address;
            char clistr[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &clientaddr_v6->sin6_addr, clistr, INET6_ADDRSTRLEN))
            {
                ip = clistr;
                port = ntohs(clientaddr_v6->sin6_port);
                return true;
            }
        }
        return false;
    }

    bool tcp_server::set_openssl(const std::string &crt_file, const std::string &key_file, openssl::version_t v, const std::string &ciphers, long flags)
    {
        this->openssl_crt_file = crt_file;
        this->openssl_key_file = key_file;
        this->openssl_manager = std::move(std::make_shared<mongols::openssl>(this->openssl_crt_file, this->openssl_key_file, v, ciphers, flags));
        this->openssl_is_ok = this->openssl_manager && this->openssl_manager->is_ok();
        return this->openssl_is_ok;
    }

    void tcp_server::set_enable_blacklist(bool b)
    {
        this->enable_blacklist = b;
    }

    void tcp_server::set_enable_security_check(bool b)
    {
        this->enable_security_check = b;
    }
    void tcp_server::set_enable_whitelist(bool b)
    {
        this->enable_whitelist = b;
    }
} // namespace mongols