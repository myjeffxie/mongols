#include <mongols/web_server.hpp>

int main(int, char **)
{
    auto f = [](const mongols::request &req) {
        if (req.method == "GET" && req.uri.find("..") == std::string::npos)
        {
            return true;
        }
        return false;
    };
    int port = 9090;
    const char *host = "127.0.0.1";
    mongols::web_server
        server(host, port, 5000, 512000, 0 /*2*/);
    server.set_root_path("localhost:9090","html");
    server.set_root_path("127.0.0.1:9090","html");
    server.set_mime_type_file("html/mime.conf");
    server.set_list_directory(true);
    server.set_enable_mmap(true);
    //    if (!server.set_openssl("openssl/localhost.crt", "openssl/localhost.key")) {
    //        return -1;
    //    }
    server.set_shutdown([&]() {
        std::cout << "process " << getpid() << " exit.\n";
    });
    server.run(f);
}