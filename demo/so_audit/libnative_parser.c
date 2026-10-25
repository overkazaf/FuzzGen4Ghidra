/*
 * libnative_parser — Simulated Android/Linux native library
 *
 * Models a typical JNI native library found in Android APKs or
 * Linux daemons. Contains multiple vulnerability patterns that
 * FuzzGen4Ghidra can detect and generate harnesses for.
 *
 * Vulnerability inventory:
 *   1. native_parse_config  — stack buffer overflow (unbounded sscanf)
 *   2. native_process_image — heap overflow via integer overflow
 *   3. native_log_event     — format string vulnerability
 *   4. native_decrypt_blob  — use-after-free
 *   5. native_exec_cmd      — command injection
 *   6. native_read_sensor   — safe (control, for scoring comparison)
 *
 * Build (macOS):
 *   clang -shared -g -O0 -o libnative_parser.dylib libnative_parser.c
 * Build (Linux/Android NDK):
 *   gcc -shared -fPIC -g -O0 -o libnative_parser.so libnative_parser.c
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ================================================================
 * VULN 1: Stack buffer overflow via unbounded sscanf
 *
 * Simulates parsing an INI/config file from JNI.
 * sscanf with %s reads until whitespace — no bounds check on key[].
 * A long key overflows the 64-byte stack buffer.
 *
 * FuzzGen score: HIGH (buffer param + sscanf + medium complexity)
 * ================================================================ */
int native_parse_config(const char *config_data, int config_len) {
    if (!config_data || config_len <= 0) return -1;

    char line[256];
    char key[64];        /* BUG: fixed-size, no bounds check */
    char value[128];
    int count = 0;

    const char *p = config_data;
    const char *end = config_data + config_len;

    while (p < end) {
        /* Read one line */
        const char *nl = memchr(p, '\n', end - p);
        int line_len = nl ? (int)(nl - p) : (int)(end - p);
        if (line_len >= (int)sizeof(line)) line_len = sizeof(line) - 1;
        memcpy(line, p, line_len);
        line[line_len] = '\0';

        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == ';' || line[0] == '\0') {
            p = nl ? nl + 1 : end;
            continue;
        }

        /* BUG: %s reads unlimited bytes into key[64] */
        if (sscanf(line, "%s = %127s", key, value) == 2) {
            count++;
        }

        p = nl ? nl + 1 : end;
    }

    return count;
}

/* ================================================================
 * VULN 2: Heap overflow via integer overflow
 *
 * Simulates image/bitmap processing in a camera or gallery app.
 * width * height * channels can overflow uint32, allocating a
 * too-small buffer, then memcpy writes past the end.
 *
 * FuzzGen score: HIGH (buffer + malloc + memcpy + complexity)
 * ================================================================ */
typedef struct {
    uint32_t magic;      /* 0x42495447 "BITG" */
    uint16_t width;
    uint16_t height;
    uint8_t  channels;   /* 1=gray, 3=RGB, 4=RGBA */
    uint8_t  reserved[3];
    /* pixel data follows */
} image_header_t;

int native_process_image(const uint8_t *data, int data_len) {
    if (!data || data_len < (int)sizeof(image_header_t)) return -1;

    const image_header_t *hdr = (const image_header_t *)data;
    if (hdr->magic != 0x42495447) return -1;
    if (hdr->channels == 0 || hdr->channels > 4) return -1;

    /* BUG: integer overflow — width * height * channels wraps to small value */
    uint32_t pixel_bytes = (uint32_t)hdr->width * hdr->height * hdr->channels;
    int header_size = sizeof(image_header_t);
    int avail = data_len - header_size;

    if (avail <= 0) return -1;

    /* Allocate based on (possibly overflowed) pixel_bytes */
    uint8_t *pixels = (uint8_t *)malloc(pixel_bytes + 1);
    if (!pixels) return -1;

    /* BUG: copies avail bytes into undersized buffer */
    int copy_len = avail < (int)pixel_bytes ? avail : (int)pixel_bytes;
    memcpy(pixels, data + header_size, copy_len);

    /* Simulate processing */
    uint64_t sum = 0;
    for (int i = 0; i < copy_len; i++) sum += pixels[i];

    free(pixels);
    return (int)(sum & 0x7FFFFFFF);
}

/* ================================================================
 * VULN 3: Format string vulnerability
 *
 * Simulates logging in an analytics/telemetry library.
 * User-controlled event_name passed directly to snprintf format.
 * Attacker can read stack with %x or write with %n.
 *
 * FuzzGen score: MEDIUM (string param + snprintf/printf)
 * ================================================================ */
static char g_log_buffer[4096];
static int g_log_offset = 0;

int native_log_event(const char *event_name, int event_code) {
    if (!event_name) return -1;

    char entry[512];
    /* BUG: event_name used as format string */
    int n = snprintf(entry, sizeof(entry), event_name, event_code);
    if (n <= 0) return -1;

    if (g_log_offset + n + 1 > (int)sizeof(g_log_buffer)) {
        g_log_offset = 0;  /* wrap around */
    }
    memcpy(g_log_buffer + g_log_offset, entry, n + 1);
    g_log_offset += n + 1;

    return n;
}

/* ================================================================
 * VULN 4: Use-after-free
 *
 * Simulates a crypto/DRM decryption routine.
 * On error path, buffer is freed but pointer is reused.
 *
 * FuzzGen score: HIGH (malloc + free + buffer + complexity)
 * ================================================================ */
int native_decrypt_blob(const uint8_t *encrypted, int enc_len,
                        uint8_t *output, int out_capacity) {
    if (!encrypted || enc_len < 4 || !output || out_capacity < enc_len)
        return -1;

    /* Simple XOR "decryption" with key from header */
    uint8_t key = encrypted[0] ^ encrypted[1] ^ encrypted[2] ^ encrypted[3];
    int body_len = enc_len - 4;

    uint8_t *temp = (uint8_t *)malloc(body_len);
    if (!temp) return -1;

    for (int i = 0; i < body_len; i++) {
        temp[i] = encrypted[4 + i] ^ key;
    }

    /* Validation: check magic after decryption */
    if (body_len >= 4 &&
        temp[0] == 'D' && temp[1] == 'E' && temp[2] == 'C' && temp[3] == 'K') {
        memcpy(output, temp + 4, body_len - 4);
        free(temp);
        return body_len - 4;
    }

    /* BUG: free on error path, but temp is used after on some compilers/paths */
    free(temp);

    /* BUG: use-after-free — reading freed memory for "error info" */
    if (body_len > 8) {
        /* Attempt to extract error code from freed buffer */
        uint32_t err_code = *(uint32_t *)(temp + 4);
        return -(int)(err_code & 0xFFFF);
    }

    return -1;
}

/* ================================================================
 * VULN 5: Command injection
 *
 * Simulates a utility function that runs a system command based
 * on user input (e.g., a diagnostic/debug handler in an Android
 * service). Input is concatenated into a shell command unsanitized.
 *
 * FuzzGen score: HIGH (string param + system/popen)
 * ================================================================ */
int native_exec_cmd(const char *device_id, const char *action) {
    if (!device_id || !action) return -1;
    if (strlen(device_id) > 64 || strlen(action) > 32) return -1;

    char cmd[256];
    /* BUG: no sanitization — device_id could contain "; rm -rf /" */
    snprintf(cmd, sizeof(cmd), "device_ctl --id %s --action %s 2>/dev/null",
             device_id, action);

    /* In a real app this would call system() or popen() */
    /* return system(cmd); */

    /* For demo safety, just return the command length */
    return (int)strlen(cmd);
}

/* ================================================================
 * SAFE: Sensor reading function (control for scoring comparison)
 *
 * No buffer operations, no dangerous calls, simple arithmetic.
 * FuzzGen should score this LOW.
 * ================================================================ */
typedef struct {
    float x, y, z;
    uint32_t timestamp;
} sensor_reading_t;

float native_read_sensor(const sensor_reading_t *reading) {
    if (!reading) return -1.0f;
    /* Compute magnitude */
    float mag = reading->x * reading->x +
                reading->y * reading->y +
                reading->z * reading->z;
    /* Cheap sqrt approximation */
    if (mag <= 0.0f) return 0.0f;
    float guess = mag * 0.5f;
    for (int i = 0; i < 5; i++) {
        guess = (guess + mag / guess) * 0.5f;
    }
    return guess;
}

/* Export version for identification */
const char *native_get_version(void) {
    return "libnative_parser 1.2.3";
}
