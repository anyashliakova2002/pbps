#include "httpd.h"
#include <stdlib.h>
#include <string.h>

static const char base64_table[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char base64_pad = '=';

char *base64_decode(const char *src) {
    if (!src || strlen(src) > MAX_B64_LEN) return NULL;
    
    size_t len = strlen(src);
    if (len % 4 != 0) return NULL;
    
    size_t padding = 0;
    if (len > 0 && src[len-1] == base64_pad) padding++;
    if (len > 1 && src[len-2] == base64_pad) padding++;
    
    size_t output_len = (len / 4) * 3 - padding;
    char *output = malloc(output_len + 1);
    if (!output) return NULL;
    
    for (size_t i = 0, j = 0; i < len;) {
        uint32_t sextet_a = src[i] == base64_pad ? 0 : strchr(base64_table, src[i++]) - base64_table;
        uint32_t sextet_b = src[i] == base64_pad ? 0 : strchr(base64_table, src[i++]) - base64_table;
        uint32_t sextet_c = src[i] == base64_pad ? 0 : strchr(base64_table, src[i++]) - base64_table;
        uint32_t sextet_d = src[i] == base64_pad ? 0 : strchr(base64_table, src[i++]) - base64_table;
        
        uint32_t triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;
        
        if (j < output_len) output[j++] = (triple >> 16) & 0xFF;
        if (j < output_len) output[j++] = (triple >> 8) & 0xFF;
        if (j < output_len) output[j++] = triple & 0xFF;
    }
    
    output[output_len] = '\0';
    return output;
}
