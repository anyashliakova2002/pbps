#include "httpd.h"
#include <sys/stat.h>
#include <stdlib.h>

#define CHUNK_SIZE 1024
#define PUBLIC_DIR "./webroot"
#define INDEX_HTML "/index.html"
#define NOT_FOUND_HTML "/404.html"

int check_auth() {
    char *auth_header = request_header("Authorization");
    if (!auth_header || strncmp(auth_header, "Basic ", 6) != 0) return 0;
    
    char *encoded = auth_header + 6;
    char *decoded = base64_decode(encoded);
    if (!decoded) return 0;
    
    char *sep = strchr(decoded, ':');
    if (!sep) {
        free(decoded);
        return 0;
    }
    
    *sep = '\0';
    int auth_result = pam_authenticate_user(decoded, sep + 1);
    free(decoded);
    return auth_result;
}

void require_auth() {
    HTTP_401;
    printf("Authentication required\n");
}

int file_exists(const char *file_name) {
    struct stat buffer;
    return stat(file_name, &buffer) == 0;
}

int read_file(const char *file_name, int *total_size) {
    char buf[CHUNK_SIZE];
    FILE *file = fopen(file_name, "r");
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

void route() {
    int response_size = 0;
    const char *status = "200";
    
    ROUTE_START()

    GET("/secure") {
        if (!check_auth()) {
            require_auth();
            status = "401";
        } else {
            HTTP_200;
            printf("Welcome to secure area!\n");
            response_size = strlen("Welcome to secure area!\n");
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

int main(int argc, char **argv) {
    char *port = argc == 1 ? "8000" : argv[1];
    
    init_openssl();
    ssl_ctx = create_context();
    configure_context(ssl_ctx, "cert.pem", "key.pem");
    
    serve_forever(port);
    
    cleanup_openssl();
    return 0;
}
