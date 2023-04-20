#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int ret;

    // Initialize OpenSSL library
    SSL_library_init();
    SSL_load_error_strings();

    // Create a new SSL_CTX object
    ctx = SSL_CTX_new(SSLv23_method());

    // Load certificate and private key
    ret = SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM);
    ret = SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM);

    // Check if the private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // Create a new SSL object
    ssl = SSL_new(ctx);

    // ... Set up a connection, perform SSL handshake, and exchange data ...

    // Free the SSL object and SSL_CTX object
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}
