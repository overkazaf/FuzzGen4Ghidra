#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* Vulnerable: stack buffer overflow when payload_len > 512 */
int process_header(const unsigned char *data, int len) {
    if (len < 7) return -1;
    /* magic check */
    if (data[0] != 0xDE || data[1] != 0xAD || data[2] != 0xBE || data[3] != 0xEF)
        return -1;
    uint8_t version = data[4];
    uint16_t payload_len = data[5] | (data[6] << 8); /* little-endian */

    char decompressed[512]; /* BUG: fixed-size stack buffer */

    if (payload_len > 0 && len >= 7 + (int)payload_len) {
        memcpy(decompressed, data + 7, payload_len); /* overflow if payload_len > 512 */
    }

    (void)version;
    return (int)payload_len;
}

/* Vulnerable: heap overflow when key exceeds 64 bytes */
int parse_kv(const char *input, int max_pairs) {
    char key[64], value[128];
    int count = 0;
    const char *p = input;
    while (*p && count < max_pairs) {
        const char *eq = strchr(p, '=');
        if (!eq) break;
        size_t klen = eq - p;
        memcpy(key, p, klen); /* BUG: no bounds check */
        key[klen] = '\0';
        const char *amp = strchr(eq + 1, '&');
        size_t vlen = amp ? (size_t)(amp - eq - 1) : strlen(eq + 1);
        if (vlen < sizeof(value)) {
            memcpy(value, eq + 1, vlen);
            value[vlen] = '\0';
        }
        count++;
        p = amp ? amp + 1 : eq + 1 + vlen;
    }
    return count;
}

/* Safe: URL decoder */
void url_decode(const char *src, char *dst, int dst_len) {
    int si = 0, di = 0;
    while (src[si] && di < dst_len - 1) {
        if (src[si] == '%' && src[si+1] && src[si+2]) {
            char hex[3] = { src[si+1], src[si+2], 0 };
            dst[di++] = (char)strtol(hex, NULL, 16);
            si += 3;
        } else {
            dst[di++] = src[si++];
        }
    }
    dst[di] = '\0';
}

const char *get_api_version(void) {
    return "1.0.0";
}

static int g_initialized = 0;
void init_globals(void) {
    g_initialized = 1;
}
