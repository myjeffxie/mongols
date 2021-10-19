
#include "openssl.hpp"
#include "util.hpp"

namespace mongols
{

    openssl::version_t openssl::version = openssl::version_t::TLSv12;
    std::string openssl::ciphers = "ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:RSA+AES128:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS"; //"AES128-GCM-SHA256";
    long openssl::flags = SSL_OP_NO_COMPRESSION | SSL_OP_NO_TICKET | SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_SINGLE_ECDH_USE | SSL_OP_SINGLE_DH_USE;
    const int openssl::ssl_session_ctx_id = 1;
    bool openssl::enable_verify = false;
    bool openssl::enable_cache = true;

    openssl::openssl(const std::string &crt_file, const std::string &key_file, openssl::version_t v, const std::string &ciphers, long flags)
        : ok(false), crt_file(crt_file), key_file(key_file), ctx(0), v(v)
    {
#if OPENSSL_VERSION_NUMBER >= 0x10100003L

        if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL) == 0)
        {
            std::cout << "init ssl failed.\n";
        }

        ERR_clear_error();

#else

        SSL_library_init();
        SSL_load_error_strings();

        OpenSSL_add_all_algorithms();

#endif

        switch (this->v)
        {
        case openssl::version_t::SSLv23:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            this->ctx = SSL_CTX_new(SSLv23_server_method());
#else
            this->ctx = SSL_CTX_new(TLS_server_method());
#endif
            break;
        case openssl::version_t::TLSv12:
            this->ctx = SSL_CTX_new(TLSv1_2_server_method());
            break;
        case openssl::version_t::TLSv13:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            this->ctx = SSL_CTX_new(TLSv1_2_server_method());
#else
            this->ctx = SSL_CTX_new(TLS_server_method());
#endif
            break;
        case openssl::version_t::DTLS:
            this->ctx = SSL_CTX_new(DTLS_server_method());
            break;
        default:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            this->ctx = SSL_CTX_new(TLSv1_2_server_method());
#else
            this->ctx = SSL_CTX_new(TLS_server_method());
#endif
            break;
        }

        // this->ctx = SSL_CTX_new(SSLv23_method());

        if (this->ctx)
        {
#ifdef SSL_OP_MICROSOFT_SESS_ID_BUG
            SSL_CTX_set_options(this->ctx, SSL_OP_MICROSOFT_SESS_ID_BUG);
#endif

#ifdef SSL_OP_NETSCAPE_CHALLENGE_BUG
            SSL_CTX_set_options(this->ctx, SSL_OP_NETSCAPE_CHALLENGE_BUG);
#endif

            /* server side options */

#ifdef SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
            SSL_CTX_set_options(this->ctx, SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG);
#endif

#ifdef SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
            SSL_CTX_set_options(this->ctx, SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER);
#endif

#ifdef SSL_OP_SSLEAY_080_CLIENT_DH_BUG
            SSL_CTX_set_options(this->ctx, SSL_OP_SSLEAY_080_CLIENT_DH_BUG);
#endif

#ifdef SSL_OP_TLS_D5_BUG
            SSL_CTX_set_options(this->ctx, SSL_OP_TLS_D5_BUG);
#endif

#ifdef SSL_OP_TLS_BLOCK_PADDING_BUG
            SSL_CTX_set_options(this->ctx, SSL_OP_TLS_BLOCK_PADDING_BUG);
#endif

#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
            SSL_CTX_set_options(this->ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif

            SSL_CTX_set_options(this->ctx, SSL_OP_SINGLE_DH_USE);

#if OPENSSL_VERSION_NUMBER >= 0x009080dfL
            /* only in 0.9.8m+ */
            SSL_CTX_clear_options(this->ctx,
                                  SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
#endif

#ifdef SSL_CTX_set_min_proto_version
            SSL_CTX_set_min_proto_version(this->ctx, 0);
            SSL_CTX_set_max_proto_version(this->ctx, TLS1_2_VERSION);
#endif

#ifdef TLS1_3_VERSION
            SSL_CTX_set_min_proto_version(this->ctx, 0);
            SSL_CTX_set_max_proto_version(this->ctx, TLS1_3_VERSION);
#endif

#ifdef SSL_OP_NO_COMPRESSION
            SSL_CTX_set_options(this->ctx, SSL_OP_NO_COMPRESSION);
#endif

#ifdef SSL_OP_NO_ANTI_REPLAY
            SSL_CTX_set_options(this->ctx, SSL_OP_NO_ANTI_REPLAY);
#endif

#ifdef SSL_OP_NO_CLIENT_RENEGOTIATION
            SSL_CTX_set_options(this->ctx, SSL_OP_NO_CLIENT_RENEGOTIATION);
#endif

#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
            SSL_CTX_set_options(this->ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif

#ifdef SSL_MODE_RELEASE_BUFFERS
            SSL_CTX_set_mode(this->ctx, SSL_MODE_RELEASE_BUFFERS);
#endif

#ifdef SSL_MODE_NO_AUTO_CHAIN
            SSL_CTX_set_mode(this->ctx, SSL_MODE_NO_AUTO_CHAIN);
#endif

            SSL_CTX_set_read_ahead(this->ctx, 1);
            SSL_CTX_set_ecdh_auto(this->ctx, 1024);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            this->ctx->freelist_max_len = 0;
#endif
            SSL_CTX_set_mode(this->ctx, SSL_MODE_RELEASE_BUFFERS | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_AUTO_RETRY);
            SSL_CTX_set_options(this->ctx, flags);
            SSL_CTX_set_cipher_list(this->ctx, ciphers.c_str());

            if (openssl::enable_cache)
            {
                SSL_CTX_set_session_cache_mode(this->ctx, SSL_SESS_CACHE_BOTH | SSL_SESS_CACHE_NO_INTERNAL);
                SSL_CTX_sess_set_cache_size(this->ctx, 1);
                SSL_CTX_set_session_id_context(this->ctx, (const unsigned char *)&openssl::ssl_session_ctx_id, sizeof(openssl::ssl_session_ctx_id));
            }
            else
            {
                SSL_CTX_set_session_cache_mode(this->ctx, SSL_SESS_CACHE_OFF);
            }

            if (SSL_CTX_use_certificate_file(this->ctx, this->crt_file.c_str(), SSL_FILETYPE_PEM) > 0)
            {
                if (SSL_CTX_use_PrivateKey_file(this->ctx, this->key_file.c_str(), SSL_FILETYPE_PEM) > 0)
                {
                    if (SSL_CTX_check_private_key(ctx) > 0)
                    {
                        if (openssl::enable_verify)
                        {
                            SSL_CTX_set_verify(this->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE, 0);
                        }
                        this->ok = true;
                    }
                }
            }
        }
    }

    openssl::~openssl()
    {
        if (this->ctx)
        {
            SSL_CTX_free(this->ctx);
        }
        EVP_cleanup();
    }

    bool openssl::is_ok() const
    {
        return this->ok;
    }

    SSL_CTX *openssl::get_ctx()
    {
        return this->ctx;
    }

    bool openssl::set_socket_and_accept(SSL *ssl, int fd)
    {
        if (SSL_set_fd(ssl, fd))
        {
            SSL_set_accept_state(ssl);
#ifdef SSL_OP_NO_RENEGOTIATION
            SSL_set_options(ssl, SSL_OP_NO_RENEGOTIATION);
#endif
            return true;
        }
        return false;
    }

    int openssl::read(SSL *ssl, char *buffer, size_t len)
    {
        ERR_clear_error();
        return SSL_read(ssl, buffer, len);
    }

    int openssl::write(SSL *ssl, const std::string &output)
    {
        ERR_clear_error();
        return SSL_write(ssl, output.c_str(), output.size());
    }

    mongols::openssl::version_t openssl::get_version() const
    {
        return this->v;
    }

    openssl::ssl::ssl(SSL_CTX *ctx)
        : data(0), rbio(0), wbio(0)
    {
        this->data = SSL_new(ctx);
        if (this->data)
        {
            SSL_set_mode(this->data, SSL_MODE_RELEASE_BUFFERS | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
        }
    }

    openssl::ssl::~ssl()
    {
        if (this->rbio)
        {
            BIO_free(this->rbio);
        }
        if (this->wbio)
        {
            BIO_free(this->wbio);
        }
        if (this->data)
        {
            SSL_shutdown(this->data);
            SSL_free(this->data);
        }
    }

    SSL *openssl::ssl::get_ssl()
    {
        return this->data;
    }

    BIO *openssl::ssl::get_rbio()
    {
        return this->rbio;
    }

    BIO *openssl::ssl::get_wbio()
    {
        return this->wbio;
    }

    void openssl::ssl::set_rbio(BIO *b)
    {
        this->rbio = b;
    }

    void openssl::ssl::set_wbio(BIO *b)
    {
        this->wbio = b;
    }

    void openssl::ssl::set_rbio()
    {
        this->rbio = BIO_new(BIO_s_mem());
    }

    void openssl::ssl::set_wbio()
    {
        this->wbio = BIO_new(BIO_s_mem());
    }

    void openssl::ssl::set_bio(BIO *b)
    {
        this->rbio = this->wbio = b;
        SSL_set_bio(this->data, b, b);
    }

    void openssl::ssl::set_bio()
    {
        this->rbio = BIO_new(BIO_s_mem());
        this->wbio = this->rbio;
    }

    void openssl::ssl::bind_bio()
    {
        SSL_set_bio(this->data, this->rbio, this->wbio);
    }

} // namespace mongols
