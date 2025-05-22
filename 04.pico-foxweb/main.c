#include "httpd.h"
#include <sys/stat.h>

#define CHUNK_SIZE 1024
#define PUBLIC_DIR "./webroot"
#define INDEX_HTML "/index.html"
#define NOT_FOUND_HTML "/404.html"

int main(int c, char **v) {
    char *port = c == 1 ? "8000" : v[1];
    serve_forever(port);
    return 0;
}

int file_exists(const char *file_name) {
    struct stat buffer;
    return (stat(file_name, &buffer) == 0);
}

int read_file(const char *file_name, int *total_size) {
    char buf[CHUNK_SIZE];
    FILE *file;
    size_t nread;
    int err = 1;
    *total_size = 0;

    file = fopen(file_name, "r");
    if (file) {
        while ((nread = fread(buf, 1, sizeof buf, file)) {
            fwrite(buf, 1, nread, stdout);
            *total_size += nread;
        }
        err = ferror(file);
        fclose(file);
    }
    return err;
}

void route() {
    int response_size = 0;
    const char *status = "200";
    
    ROUTE_START()

    GET("/") {
        char index_html[20];
        sprintf(index_html, "%s%s", PUBLIC_DIR, INDEX_HTML);

        HTTP_200;
        if (file_exists(index_html)) {
            read_file(index_html, &response_size);
        } else {
            char *msg = "Hello! You are using %s\n\n";
            char *user_agent = request_header("User-Agent");
            printf(msg, user_agent);
            response_size = strlen(msg) + (user_agent ? strlen(user_agent) : 0);
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
        char *msg1 = "Wow, seems that you POSTed %d bytes.\n";
        char *msg2 = "Fetch the data using `payload` variable.\n";
        printf(msg1, payload_size);
        printf(msg2);
        response_size = strlen(msg1) + strlen(msg2) + 20;
        if (payload_size > 0) {
            printf("Request body: %s", payload);
            response_size += strlen(payload) + 13;
        }
        status = "201";
    }

    GET(uri) {
        char file_name[255];
        sprintf(file_name, "%s%s", PUBLIC_DIR, uri);

        if (file_exists(file_name)) {
            HTTP_200;
            read_file(file_name, &response_size);
            status = "200";
        } else {
            HTTP_404;
            sprintf(file_name, "%s%s", PUBLIC_DIR, NOT_FOUND_HTML);
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
