#include "httpd.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/mman.h>
#include <signal.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

#define MAX_CONNECTIONS 1000
#define BUF_SIZE 65535
#define QUEUE_SIZE 1000000
#define LOG_FILE "/var/log/foxweb.log"

static int listenfd;
int *clients;
static char *buf;
auth_attempt auth_history[MAX_CONNECTIONS];

/* SSL initialization */
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        syslog(LOG_ERR, "Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    SSL_CTX_set_options(ctx, 
        SSL_OP_NO_SSLv2 | 
        SSL_OP_NO_SSLv3 | 
        SSL_OP_NO_TLSv1 |
        SSL_OP_NO_COMPRESSION |
        SSL_OP_CIPHER_SERVER_PREFERENCE);
    
    SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384");
    SSL_CTX_set_ecdh_auto(ctx, 1);
    
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        syslog(LOG_ERR, "Failed to load SSL certificates");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    if (!SSL_CTX_check_private_key(ctx)) {
        syslog(LOG_ERR, "Private key does not match certificate");
        exit(EXIT_FAILURE);
    }
}

void cleanup_openssl() {
    SSL_CTX_free(ssl_ctx);
    EVP_cleanup();
}

/* PAM authentication */
static int pam_conv_func(int num_msg, const struct pam_message **msg,
                        struct pam_response **resp, void *appdata_ptr) {
    pam_conv_data *data = (pam_conv_data *)appdata_ptr;
    struct pam_response *response = calloc(num_msg, sizeof(struct pam_response));
    if (!response) return PAM_BUF_ERR;
    
    for (int i = 0; i < num_msg; i++) {
        switch (msg[i]->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
                response[i].resp = strdup(data->password);
                break;
            case PAM_PROMPT_ECHO_ON:
                response[i].resp = strdup(data->username);
                break;
            default:
                response[i].resp = NULL;
                break;
        }
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF && !response[i].resp) {
            for (int j = 0; j < i; j++) free(response[j].resp);
            free(response);
            return PAM_BUF_ERR;
        }
    }
    
    *resp = response;
    return PAM_SUCCESS;
}

int pam_authenticate_user(const char *username, const char *password) {
    pam_handle_t *pamh = NULL;
    pam_conv_data data = { (char*)username, (char*)password };
    struct pam_conv conv = { pam_conv_func, &data };
    
    int ret = pam_start("httpd", username, &conv, &pamh);
    if (ret != PAM_SUCCESS) {
        syslog(LOG_WARNING, "PAM start failed for user %s: %s", username, pam_strerror(pamh, ret));
        return 0;
    }
    
    ret = pam_authenticate(pamh, 0);
    if (ret != PAM_SUCCESS) {
        syslog(LOG_WARNING, "Auth failed for user %s: %s", username, pam_strerror(pamh, ret));
        pam_end(pamh, ret);
        return 0;
    }
    
    ret = pam_acct_mgmt(pamh, 0);
    if (ret == PAM_NEW_AUTHTOK_REQD) {
        syslog(LOG_NOTICE, "Password change required for user %s", username);
        pam_end(pamh, ret);
        return -1;
    } else if (ret != PAM_SUCCESS) {
        syslog(LOG_WARNING, "Account check failed for user %s: %s", username, pam_strerror(pamh, ret));
        pam_end(pamh, ret);
        return 0;
    }
    
    pam_end(pamh, PAM_SUCCESS);
    return 1;
}

/* Rate limiting */
int check_auth_limit(const char *ip) {
    time_t now = time(NULL);
    
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (strcmp(auth_history[i].ip, ip) == 0) {
            if (auth_history[i].attempts >= MAX_AUTH_ATTEMPTS && 
                now - auth_history[i].last_attempt < AUTH_BLOCK_TIME) {
                return 0;
            }
            if (now - auth_history[i].last_attempt > AUTH_BLOCK_TIME) {
                auth_history[i].attempts = 0;
            }
            return 1;
        }
    }
    
    // Add new entry
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (auth_history[i].ip[0] == '\0') {
            strncpy(auth_history[i].ip, ip, INET_ADDRSTRLEN);
            auth_history[i].attempts = 0;
            auth_history[i].last_attempt = now;
            return 1;
        }
    }
    
    return 1;
}

void log_failed_auth(const char *ip, const char *username) {
    syslog(LOG_WARNING, "Failed auth attempt from %s for user %s", ip, username ? username : "unknown");
    
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (strcmp(auth_history[i].ip, ip) == 0) {
            auth_history[i].attempts++;
            auth_history[i].last_attempt = time(NULL);
            break;
        }
    }
}

/* Logging */
void log_access(const char *status, int response_size) {
    FILE *log_file = fopen(LOG_FILE, "a");
    if (!log_file) {
        syslog(LOG_ERR, "Failed to open log file: %s", strerror(errno));
        return;
    }

    time_t now;
    time(&now);
    struct tm *tm = localtime(&now);
    char timestamp[128];
    strftime(timestamp, sizeof(timestamp), "%d/%b/%Y:%H:%M:%S %z", tm);

    const char *user_agent = request_header("User-Agent") ?: "-";
    const char *referer = request_header("Referer") ?: "-";

    fprintf(log_file, "%s - - [%s] \"%s %s %s\" %s %d \"%s\" \"%s\"\n",
            client_ip, timestamp, method, uri, prot, status, response_size, referer, user_agent);

    fclose(log_file);
}

/* Server functions */
void start_server(const char *port) {
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, port, &hints, &res) != 0) {
        syslog(LOG_ERR, "getaddrinfo() error: %s", strerror(errno));
        exit(1);
    }

    for (p = res; p != NULL; p = p->ai_next) {
        int option = 1;
        listenfd = socket(p->ai_family, p->ai_socktype, 0);
        setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
        if (listenfd == -1) continue;
        if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0) break;
    }

    if (p == NULL) {
        syslog(LOG_ERR, "socket() or bind() error: %s", strerror(errno));
        exit(1);
    }

    freeaddrinfo(res);

    if (listen(listenfd, QUEUE_SIZE) != 0) {
        syslog(LOG_ERR, "listen() error: %s", strerror(errno));
        exit(1);
    }
}

/* Request handling */
char *request_header(const char *name) {
    header_t *h = reqhdr;
    while (h->name) {
        if (strcmp(h->name, name) == 0)
            return h->value;
        h++;
    }
    return NULL;
}

header_t *request_headers(void) { 
    return reqhdr; 
}

static void uri_unescape(char *uri) {
    char chr = 0;
    char *src = uri;
    char *dst = uri;

    while (*src && !isspace((int)(*src)) && (*src != '%'))
        src++;

    dst = src;
    while (*src && !isspace((int)(*src))) {
        if (*src == '+')
            chr = ' ';
        else if ((*src == '%') && src[1] && src[2]) {
            src++;
            chr = ((*src & 0x0F) + 9 * (*src > '9')) * 16;
            src++;
            chr += ((*src & 0x0F) + 9 * (*src > '9'));
        } else
            chr = *src;
        *dst++ = chr;
        src++;
    }
    *dst = '\0';
}

void respond(int slot) {
    int rcvd;

    buf = malloc(BUF_SIZE);
    if (!buf) {
        syslog(LOG_ERR, "malloc() failed: %s", strerror(errno));
        return;
    }

    rcvd = recv(clients[slot], buf, BUF_SIZE, 0);

    if (rcvd < 0) {
        syslog(LOG_ERR, "recv() error: %s", strerror(errno));
    } else if (rcvd == 0) {
        syslog(LOG_INFO, "Client disconnected");
    } else {
        buf[rcvd] = '\0';

        method = strtok(buf, " \t\r\n");
        uri = strtok(NULL, " \t");
        prot = strtok(NULL, " \t\r\n");

        if (!method || !uri || !prot) {
            syslog(LOG_WARNING, "Malformed request");
            goto cleanup;
        }

        uri_unescape(uri);
        syslog(LOG_INFO, "Request: %s %s", method, uri);

        qs = strchr(uri, '?');
        if (qs)
            *qs++ = '\0';
        else
            qs = uri - 1;

        /* Parse headers */
        header_t *h = reqhdr;
        char *t, *t2;
        while (h < reqhdr + 16) {
            char *key = strtok(NULL, "\r\n: \t");
            if (!key) break;

            char *val = strtok(NULL, "\r\n");
            while (val && *val == ' ') val++;

            h->name = key;
            h->value = val;
            h++;
            
            t = val + 1 + strlen(val);
            if (t[1] == '\r' && t[2] == '\n') break;
        }

        /* Handle payload */
        t = strtok(NULL, "\r\n");
        t2 = request_header("Content-Length");
        payload = t;
        payload_size = t2 ? atol(t2) : (rcvd - (t - buf));

        /* Process request */
        int clientfd = clients[slot];
        dup2(clientfd, STDOUT_FILENO);
        close(clientfd);

        route();

        fflush(stdout);
        shutdown(STDOUT_FILENO, SHUT_WR);
        close(STDOUT_FILENO);
    }

cleanup:
    free(buf);
}

void serve_forever(const char *PORT) {
    struct sockaddr_in clientaddr;
    socklen_t addrlen;
    int slot = 0;

    syslog(LOG_INFO, "Server starting on port %s", PORT);

    clients = mmap(NULL, sizeof(*clients) * MAX_CONNECTIONS,
                 PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (clients == MAP_FAILED) {
        syslog(LOG_ERR, "mmap() failed: %s", strerror(errno));
        exit(1);
    }

    for (int i = 0; i < MAX_CONNECTIONS; i++)
        clients[i] = -1;

    start_server(PORT);
    signal(SIGCHLD, SIG_IGN);

    while (1) {
        addrlen = sizeof(clientaddr);
        clients[slot] = accept(listenfd, (struct sockaddr *)&clientaddr, &addrlen);

        if (clients[slot] < 0) {
            syslog(LOG_ERR, "accept() error: %s", strerror(errno));
            continue;
        }

        client_ip = inet_ntoa(clientaddr.sin_addr);
        syslog(LOG_INFO, "Connection from %s", client_ip);

        if (fork() == 0) {
            close(listenfd);
            respond(slot);
            close(clients[slot]);
            exit(0);
        } else {
            close(clients[slot]);
        }

        while (clients[slot] != -1)
            slot = (slot + 1) % MAX_CONNECTIONS;
    }
}
