#include "httpd.h"
#include <stdlib.h>
#include <string.h>

static const char base64_table[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char base64_pad = '=';

char *base64_decode(const char *src) {
    size_t len = strlen(src);
    if (len % 4 != 0) return NULL;
    
    size_t padding = 0;
    if (len > 0 && src[len-1] == base64_pad) padding++;
    if (len > 1 && src[len-2] == base64_pad) padding++;
    
    size_t output_len = (len / 4) * 3 - padding;
    char *output = malloc(output_len + 1);
    if (!output) return NULL;
    
    for (size_t i = 0, j = 0; i < len;) {
        uint32_t sextet_a = src[i] == base64_pad ? 0 & i++ : strchr(base64_table, src[i++]) - base64_table;
        uint32_t sextet_b = src[i] == base64_pad ? 0 & i++ : strchr(base64_table, src[i++]) - base64_table;
        uint32_t sextet_c = src[i] == base64_pad ? 0 & i++ : strchr(base64_table, src[i++]) - base64_table;
        uint32_t sextet_d = src[i] == base64_pad ? 0 & i++ : strchr(base64_table, src[i++]) - base64_table;
        
        uint32_t triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) + (sextet_c << 1 * 6) + (sextet_d << 0 * 6);
        
        if (j < output_len) output[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < output_len) output[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < output_len) output[j++] = (triple >> 0 * 8) & 0xFF;
    }
    
    output[output_len] = '\0';
    return output;
}
