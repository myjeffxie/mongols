
#include <mongols/tcp_server.hpp>
#include <mongols/tcp_threading_server.hpp>
#include <mongols/lib/args.hxx>
#include <unistd.h>

int main(int argc, char **argv)
{
    args::ArgumentParser parser("This is a tcp server program.", "This goes after the options.");
    args::HelpFlag help(parser, "help", "Display this help menu", {'h', "help"});
    args::ValueFlag<int> to_other(parser, "to_other", "The to_other flag", {"to_other"});
    bool _to_other = true;

    try
    {
        parser.ParseCLI(argc, argv);
    }
    catch (args::Help &)
    {
        std::cout << parser;
        return 0;
    }
    catch (args::ParseError &e)
    {
        std::cerr << e.what() << std::endl;
        std::cerr << parser;
        return -1;
    }
    catch (args::ValidationError &e)
    {
        std::cerr << e.what() << std::endl;
        std::cerr << parser;
        return -1;
    }

    if (to_other)
    {
        _to_other = args::get(to_other) == 0 ? false : true;
    }

    std::cout << "to_other: " << std::boolalpha << _to_other << std::endl;

    auto f = [_to_other](const std::pair<char *, size_t> &input, bool &keepalive, bool &send_to_other, mongols::tcp_server::client_t &client, mongols::tcp_server::filter_handler_function &send_to_other_filter)
    {
        keepalive = KEEPALIVE_CONNECTION;
        send_to_other = _to_other;
        return std::string(input.first, input.second);
    };
    int port = 9090;
    const char *host = "127.0.0.1";

    mongols::tcp_server
        //    mongols::tcp_threading_server
        server(host, port);
    //    if (!server.set_openssl("openssl/localhost.crt", "openssl/localhost.key")) {
    //        return -1;
    //    }
    server.set_shutdown([&]()
                        { std::cout << "process " << getpid() << " exit.\n"; });
    server.set_whitelist_file("etc/whitelist.txt");
    server.set_enable_whitelist(true);
    server.run(f);
}