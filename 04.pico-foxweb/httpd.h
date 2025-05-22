#ifndef _HTTPD_H___
#define _HTTPD_H___

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <security/pam_appl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Client request
extern char *method, *uri, *qs, *prot, *payload;
extern int payload_size;
extern char *client_ip;
extern SSL_CTX *ssl_ctx;

// PAM authentication
typedef struct {
    char *username;
    char *password;
} pam_conv_data;

int pam_authenticate_user(const char *username, const char *password);
void init_openssl();
SSL_CTX *create_context();
void configure_context(SSL_CTX *ctx, const char *cert_file, const char *key_file);
void cleanup_openssl();
char *base64_decode(const char *src);

// Server control functions
void serve_forever(const char *PORT);
void log_access(const char *status, int response_size);

char *request_header(const char *name);

typedef struct {
    char *name, *value;
} header_t;
static header_t reqhdr[17] = {{"\0", "\0"}};
header_t *request_headers(void);

void route();

// Response
#define RESPONSE_PROTOCOL "HTTP/1.1"

#define HTTP_200 printf("%s 200 OK\n\n", RESPONSE_PROTOCOL)
#define HTTP_201 printf("%s 201 Created\n\n", RESPONSE_PROTOCOL)
#define HTTP_401 printf("%s 401 Unauthorized\nWWW-Authenticate: Basic realm=\"Secure Area\"\n\n", RESPONSE_PROTOCOL)
#define HTTP_404 printf("%s 404 Not found\n\n", RESPONSE_PROTOCOL)
#define HTTP_500 printf("%s 500 Internal Server Error\n\n", RESPONSE_PROTOCOL)

// Routing macros
#define ROUTE_START() if (0) {
#define ROUTE(METHOD, URI) } else if (strcmp(URI, uri) == 0 && strcmp(METHOD, method) == 0) {
#define GET(URI) ROUTE("GET", URI)
#define POST(URI) ROUTE("POST", URI)
#define ROUTE_END() } else HTTP_500;

#endif
