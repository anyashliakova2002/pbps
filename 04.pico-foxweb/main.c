#include "httpd.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Global variables */
char *method, *uri, *qs, *prot, *payload;
int payload_size;
char *client_ip;
SSL_CTX *ssl_ctx;
auth_attempt auth_history[MAX_CONNECTIONS];
header_t reqhdr[17] = {{"\0", "\0"}};

/* Authentication check */
int check_auth() {
    if (!check_auth_limit(client_ip)) {
        return -2; // Rate limit exceeded
    }

    char *auth_header = request_header("Authorization");
    if (!auth_header || strncmp(auth_header, "Basic ", 6) != 0) {
        return 0;
    }

    char *encoded = auth_header + 6;
    if (strlen(encoded) > MAX_B64_LEN) {
        return 0;
    }

    char *decoded = base64_decode(encoded);
    if (!decoded) {
        return 0;
    }

    char *sep = strchr(decoded, ':');
    if (!sep) {
        free(decoded);
        return 0;
    }

    *sep = '\0';
    char *username = decoded;
    char *password = sep + 1;

    int auth_result = pam_authenticate_user(username, password);
    if (auth_result <= 0) {
        log_failed_auth(client_ip, username);
    }

    free(decoded);
    return auth_result;
}

/* Auth required response */
void require_auth(int auth_status) {
    switch (auth_status) {
        case -2: HTTP_429; printf("Too many attempts. Try again in %d seconds.\n", AUTH_BLOCK_TIME); break;
        case -1: HTTP_401; printf("Password change required\n"); break;
        default: HTTP_401; printf("Authentication required\n"); break;
    }
}

/* File operations */
int file_exists(const char *file_name) {
    struct stat buffer;
    return stat(file_name, &buffer) == 0;
}

int read_file(const char *file_name, int *total_size) {
    char buf[CHUNK_SIZE];
    FILE *file = fopen(file_name, "rb");
    *total_size = 0;

    if (file) {
        size_t nread;
        while ((nread = fread(buf, 1, sizeof(buf), file)) {
            fwrite(buf, 1, nread, stdout);
            *total_size += nread;
        }
        fclose(file);
        return 0;
    }
    return 1;
}

/* Main router */
void route() {
    int response_size = 0;
    const char *status = "200";
    
    ROUTE_START()

    GET("/secure") {
        int auth_status = check_auth();
        if (auth_status <= 0) {
            require_auth(auth_status);
            status = auth_status == -2 ? "429" : "401";
        } else {
            HTTP_200;
            printf("Secure area. Welcome!\n");
            response_size = strlen("Secure area. Welcome!\n");
            status = "200";
        }
    }

    GET("/") {
        char index_html[256];
        snprintf(index_html, sizeof(index_html), "%s%s", PUBLIC_DIR, INDEX_HTML);

        HTTP_200;
        if (file_exists(index_html)) {
            read_file(index_html, &response_size);
        } else {
            char *msg = "Hello! You are using %s\n\n";
            char *user_agent = request_header("User-Agent");
            printf(msg, user_agent ? user_agent : "unknown");
            response_size = strlen(msg) + (user_agent ? strlen(user_agent) : 7);
        }
        status = "200";
    }

    GET("/test") {
        HTTP_200;
        printf("List of request headers:\n\n");
        response_size += strlen("List of request headers:\n\n");

        header_t *h = request_headers();
        while (h->name) {
            printf("%s: %s\n", h->name, h->value);
            response_size += strlen(h->name) + strlen(h->value) + 3;
            h++;
        }
        status = "200";
    }

    POST("/") {
        HTTP_201;
        char *msg1 = "Received %d bytes\n";
        char *msg2 = "Payload: %.*s\n";
        printf(msg1, payload_size);
        if (payload_size > 0) {
            printf(msg2, payload_size > 100 ? 100 : payload_size, payload);
        }
        response_size = strlen(msg1) + (payload_size > 0 ? strlen(msg2) + (payload_size > 100 ? 100 : payload_size) : 0);
        status = "201";
    }

    GET(uri) {
        char file_name[512];
        snprintf(file_name, sizeof(file_name), "%s%s", PUBLIC_DIR, uri);

        if (file_exists(file_name)) {
            HTTP_200;
            read_file(file_name, &response_size);
            status = "200";
        } else {
            HTTP_404;
            snprintf(file_name, sizeof(file_name), "%s%s", PUBLIC_DIR, NOT_FOUND_HTML);
            if (file_exists(file_name)) {
                read_file(file_name, &response_size);
            } else {
                char *msg = "404 Not Found\n";
                printf(msg);
                response_size = strlen(msg);
            }
            status = "404";
        }
    }

    ROUTE_END()
    
    log_access(status, response_size);
}

/* Entry point */
int main(int argc, char **argv) {
    openlog("foxweb", LOG_PID|LOG_CONS, LOG_DAEMON);
    
    char *port = argc == 1 ? "8000" : argv[1];
    
    // Initialize SSL
    init_openssl();
    ssl_ctx = create_context();
    configure_context(ssl_ctx);
    
    // Start server
    serve_forever(port);
    
    // Cleanup
    cleanup_openssl();
    closelog();
    return 0;
}
