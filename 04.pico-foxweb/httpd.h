#ifndef _HTTPD_H___
#define _HTTPD_H___

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <security/pam_appl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>

/* Constants */
#define MAX_B64_LEN 1024
#define MAX_AUTH_ATTEMPTS 3
#define AUTH_BLOCK_TIME 300
#define MAX_CONNECTIONS 1000
#define BUF_SIZE 65536
#define CHUNK_SIZE 1024
#define PUBLIC_DIR "./webroot"
#define INDEX_HTML "/index.html"
#define NOT_FOUND_HTML "/404.html"

/* Rate limiting structure */
typedef struct {
    char ip[INET_ADDRSTRLEN];
    int attempts;
    time_t last_attempt;
} auth_attempt;

/* Client request data */
extern char *method;    // "GET" or "POST"
extern char *uri;       // "/path"
extern char *qs;        // "a=1&b=2"
extern char *prot;      // "HTTP/1.1"
extern char *payload;   // POST data
extern int payload_size;
extern char *client_ip;
extern SSL_CTX *ssl_ctx;
extern auth_attempt auth_history[MAX_CONNECTIONS];

/* PAM authentication */
typedef struct {
    char *username;
    char *password;
} pam_conv_data;

/* SSL functions */
void init_openssl();
SSL_CTX *create_context();
void configure_context(SSL_CTX *ctx);
void cleanup_openssl();

/* Authentication functions */
int pam_authenticate_user(const char *username, const char *password);
int check_auth_limit(const char *ip);
void log_failed_auth(const char *ip, const char *username);
char *base64_decode(const char *src);

/* Server control */
void serve_forever(const char *PORT);
void log_access(const char *status, int response_size);

/* Request handling */
char *request_header(const char *name);

typedef struct {
    char *name, *value;
} header_t;
static header_t reqhdr[17] = {{"\0", "\0"}};
header_t *request_headers(void);

/* User-implemented router */
void route();

/* Response macros */
#define RESPONSE_PROTOCOL "HTTP/1.1"
#define HTTP_200 printf("%s 200 OK\n\n", RESPONSE_PROTOCOL)
#define HTTP_201 printf("%s 201 Created\n\n", RESPONSE_PROTOCOL)
#define HTTP_401 printf("%s 401 Unauthorized\nWWW-Authenticate: Basic realm=\"Secure Area\"\nRetry-After: 5\n\n", RESPONSE_PROTOCOL)
#define HTTP_403 printf("%s 403 Forbidden\n\n", RESPONSE_PROTOCOL)
#define HTTP_404 printf("%s 404 Not found\n\n", RESPONSE_PROTOCOL)
#define HTTP_429 printf("%s 429 Too Many Requests\nRetry-After: %d\n\n", RESPONSE_PROTOCOL, AUTH_BLOCK_TIME)
#define HTTP_500 printf("%s 500 Internal Server Error\n\n", RESPONSE_PROTOCOL)

/* Routing macros */
#define ROUTE_START() if (0) {
#define ROUTE(METHOD, URI) } else if (strcmp(URI, uri) == 0 && strcmp(METHOD, method) == 0) {
#define GET(URI) ROUTE("GET", URI)
#define POST(URI) ROUTE("POST", URI)
#define ROUTE_END() } else HTTP_500;

#endif
